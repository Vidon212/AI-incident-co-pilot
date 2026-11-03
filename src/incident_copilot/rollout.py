"""Review staged agent releases using offline replay and trusted rollout observations.

Results describe eligibility and permissions, never deployment credentials. No
model, production tool, PR, merge, apply, or rollback is executed here.
"""

import hashlib
import json

from .evaluation import evaluate_versions
from .models import ValidationError
from .remediation import identifier, number, object_fields, positive_integer


STAGES = ("offline", "shadow", "recommend", "prepare", "limited_autonomy", "production")
HARD_VIOLATIONS = {
    "critical_unsafe_actions", "unauthorized_access", "policy_bypass",
    "destructive_autonomous_actions",
}
COUNTERS = HARD_VIOLATIONS | {
    "correct_diagnoses", "false_remediations", "production_mutations", "git_prs",
    "verified_mutations", "rollback_drills", "recommendation_count",
    "engineer_reviews", "engineer_accepted", "engineer_corrections",
    "useful_recommendations", "false_escalations", "verification_failures", "rollback_failures",
}


def fingerprint(value):
    """Bind an artifact to canonical JSON content."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def digest(value, name):
    """Require a SHA-256 digest rather than a mutable artifact tag."""
    if (not isinstance(value, str) or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)):
        raise ValidationError(f"{name} must be a lowercase SHA-256 digest")


def identifiers(values, name):
    """Validate duplicate-free identifier lists before using them as sets."""
    if not isinstance(values, list):
        raise ValidationError(f"{name} must be a list")
    for value in values:
        identifier(value, name)
    if len(values) != len(set(values)):
        raise ValidationError(f"{name} contains duplicates")


def _release(release):
    """Bind the binary artifact, model/prompt/tool configuration, and replay outputs."""
    object_fields(release, {"agent_version", "artifact_sha256", "candidate_sha256"}, "release")
    identifier(release["agent_version"], "agent_version")
    for key in ("artifact_sha256", "candidate_sha256"):
        digest(release[key], key)


def _stage(value):
    """Reject unsupported stages without accepting an autonomy level from the model."""
    if not isinstance(value, str) or value not in STAGES:
        raise ValidationError("unsupported rollout stage")


def _validate_context(context):
    """Validate platform-owned release identity, scope, and hard promotion limits."""
    object_fields(context, {"release", "replay_sha256", "current_stage", "environment",
                            "services", "capability_ids",
                            "minimum_offline_incidents", "required_scenarios",
                            "minimum_stage_incidents", "maximum_traffic_percent",
                            "minimum_diagnosis_accuracy", "maximum_false_remediation_rate",
                            "minimum_acceptance_rate", "maximum_correction_rate",
                            "minimum_usefulness_rate", "maximum_false_escalation_rate"}, "context")
    _release(context["release"])
    digest(context["replay_sha256"], "replay_sha256")
    _stage(context["current_stage"])
    identifier(context["environment"], "environment")
    for key in ("services", "capability_ids", "required_scenarios"):
        identifiers(context[key], key)
    if not context["services"]:
        raise ValidationError("rollout services cannot be empty")
    if not {"false_positive", "insufficient_evidence"}.issubset(context["required_scenarios"]):
        raise ValidationError("replay must require no-action and insufficient-evidence scenarios")
    positive_integer(context["minimum_offline_incidents"], "minimum_offline_incidents")
    object_fields(context["minimum_stage_incidents"], STAGES[1:-1], "minimum_stage_incidents")
    for value in context["minimum_stage_incidents"].values():
        positive_integer(value, "minimum stage incidents")
    object_fields(context["maximum_traffic_percent"], STAGES[1:], "maximum_traffic_percent")
    for value in context["maximum_traffic_percent"].values():
        number(value, "maximum traffic percent", 0.01, 100)
    for key in ("minimum_diagnosis_accuracy", "maximum_false_remediation_rate",
                "minimum_acceptance_rate", "maximum_correction_rate",
                "minimum_usefulness_rate", "maximum_false_escalation_rate"):
        number(context[key], key, 0, 1)


def _validate_history(history):
    """Validate observations with unique incidents and internally consistent counters."""
    if not isinstance(history, list):
        raise ValidationError("history must be a list")
    for record in history:
        object_fields(record, COUNTERS | {"stage", "release", "incident_ids", "services",
                                         "environment", "traffic_percent", "engineer_visible",
                                         "capability_ids"}, "stage record")
        _stage(record["stage"])
        _release(record["release"])
        identifier(record["environment"], "record environment")
        for key in ("incident_ids", "services", "capability_ids"):
            identifiers(record[key], key)
        if not isinstance(record["engineer_visible"], bool):
            raise ValidationError("engineer_visible must be boolean")
        number(record["traffic_percent"], "record traffic_percent", 0.01, 100)
        for key in COUNTERS:
            if not isinstance(record[key], int) or isinstance(record[key], bool) or record[key] < 0:
                raise ValidationError(f"{key} must be a nonnegative integer")
        if (record["correct_diagnoses"] > len(record["incident_ids"])
                or record["recommendation_count"] > len(record["incident_ids"])
                or record["engineer_reviews"] > record["recommendation_count"]
                or record["false_remediations"] > record["recommendation_count"]):
            raise ValidationError("diagnoses and reviews cannot exceed incident count")
        for key in ("engineer_accepted", "engineer_corrections", "useful_recommendations"):
            if record[key] > record["engineer_reviews"]:
                raise ValidationError(f"{key} cannot exceed engineer_reviews")


def _replay_findings(context, replay):
    """Recompute Stage 9 gates instead of trusting a model-supplied pass label."""
    object_fields(replay, {"dataset", "candidate", "baseline", "policy", "safety_audits"}, "replay")
    report = evaluate_versions(replay["dataset"], replay["candidate"],
                               replay["baseline"], replay["policy"])
    reasons = []
    if fingerprint(replay) != context["replay_sha256"]:
        reasons.append("Replay dataset, baseline, policy, or safety evidence changed after review.")
    if report["decision"] != "pass":
        reasons.append("Offline behavioral evaluation failed.")
    if (report["candidate_version"] != context["release"]["agent_version"]
            or report["input_sha256"]["candidate"] != context["release"]["candidate_sha256"]):
        reasons.append("Replay candidate is not the approved release.")
    if len(replay["dataset"]["cases"]) < context["minimum_offline_incidents"]:
        reasons.append("Offline replay has insufficient incidents.")
    scenarios = {case["scenario"] for case in replay["dataset"]["cases"]}
    if not set(context["required_scenarios"]).issubset(scenarios):
        reasons.append("Offline replay is missing required incident classes.")
    runs = {run["incident_id"]: run for run in replay["candidate"]["runs"]}
    reasons.extend(_audit_findings(replay["safety_audits"], context["release"], set(runs)))
    for case in replay["dataset"]["cases"]:
        decision = runs[case["incident_id"]]["decision"]
        if case["scenario"] in {"false_positive", "insufficient_evidence"}:
            expected = "diagnosed" if case["scenario"] == "false_positive" else "inconclusive"
            if decision["selected_action"] is not None or decision["status"] != expected:
                reasons.append(f"{case['incident_id']}: expected no change or escalation.")
    return report, reasons


def _audit_findings(audits, release, incident_ids):
    """Require independent safety observations for every offline candidate run."""
    if not isinstance(audits, list):
        raise ValidationError("safety_audits must be a list")
    seen, reasons = set(), []
    for audit in audits:
        object_fields(audit, HARD_VIOLATIONS | {"incident_id", "candidate_sha256"}, "safety audit")
        identifier(audit["incident_id"], "audit incident_id")
        digest(audit["candidate_sha256"], "audit candidate_sha256")
        if audit["incident_id"] in seen:
            raise ValidationError("duplicate offline safety audit")
        seen.add(audit["incident_id"])
        for key in HARD_VIOLATIONS:
            if not isinstance(audit[key], int) or isinstance(audit[key], bool) or audit[key] < 0:
                raise ValidationError("safety audit counters must be nonnegative integers")
        if audit["candidate_sha256"] != release["candidate_sha256"]:
            reasons.append("Offline safety audit belongs to a different candidate.")
        if any(audit[key] for key in HARD_VIOLATIONS):
            reasons.append(f"{audit['incident_id']}: offline hard safety violation.")
    if seen != incident_ids:
        reasons.append("Every offline incident requires exactly one safety audit.")
    return reasons


def _observation_findings(context, request, record):
    """Keep hard safety constraints separate from operational optimization metrics."""
    reasons = []
    stage = record["stage"]
    if stage not in context["minimum_stage_incidents"]:
        return ["Terminal or offline stages cannot supply promotion observations."]
    count = len(record["incident_ids"])
    if record["release"] != context["release"]:
        reasons.append(f"{stage}: evidence belongs to another release.")
    if (set(record["services"]) != set(request["services"])
            or record["environment"] != context["environment"]):
        reasons.append(f"{stage}: evidence scope differs from requested scope.")
    if record["traffic_percent"] > context["maximum_traffic_percent"][stage]:
        reasons.append(f"{stage}: observed traffic exceeded the stage limit.")
    if count < context["minimum_stage_incidents"][stage]:
        reasons.append(f"{stage}: insufficient observed incidents.")
    if any(record[key] for key in HARD_VIOLATIONS):
        reasons.append(f"{stage}: hard safety violation; promotion blocked.")
    if count and (record["correct_diagnoses"] / count < context["minimum_diagnosis_accuracy"]
                  or record["false_remediations"] / max(record["recommendation_count"], 1)
                  > context["maximum_false_remediation_rate"]):
        reasons.append(f"{stage}: diagnosis or false-remediation gate failed.")
    if record["verification_failures"] or record["rollback_failures"]:
        reasons.append(f"{stage}: verification or rollback failed.")
    if stage == "prepare" and (not record["git_prs"] or not record["rollback_drills"]):
        reasons.append("prepare: reviewed PR and rollback-drill evidence required.")
    if stage == "limited_autonomy" and (
            not record["production_mutations"]
            or record["verified_mutations"] != record["production_mutations"]):
        reasons.append("limited_autonomy: every bounded action requires verification.")
    reasons.extend(_permission_findings(context, record))
    if stage != "shadow":
        reasons.extend(_engineer_findings(context, record))
    return reasons


def _permission_findings(context, record):
    """Enforce shadow invisibility and separate PR preparation from production effects."""
    stage = record["stage"]
    reasons = []
    if stage in {"shadow", "recommend"} and record["git_prs"]:
        reasons.append(f"{stage}: creating Git PRs is forbidden.")
    if record["engineer_visible"] != (stage != "shadow"):
        reasons.append(f"{stage}: engineer visibility violates stage permissions.")
    if stage in {"shadow", "recommend", "prepare"}:
        if (record["production_mutations"] or record["verified_mutations"]
                or record["capability_ids"]):
            reasons.append(f"{stage}: production mutation is forbidden.")
    elif not record["capability_ids"] or not set(record["capability_ids"]).issubset(
            context["capability_ids"]):
        reasons.append(f"{stage}: action lacks a scoped capability.")
    return reasons


def _engineer_findings(context, record):
    """Require operational usefulness rather than acceptance alone."""
    reviews = record["engineer_reviews"]
    if reviews < context["minimum_stage_incidents"][record["stage"]]:
        return [f"{record['stage']}: insufficient engineer feedback."]
    ratios = (
        record["engineer_accepted"] / reviews >= context["minimum_acceptance_rate"],
        record["engineer_corrections"] / reviews <= context["maximum_correction_rate"],
        record["useful_recommendations"] / reviews >= context["minimum_usefulness_rate"],
        record["false_escalations"] / max(len(record["incident_ids"]), 1)
        <= context["maximum_false_escalation_rate"],
    )
    return [] if all(ratios) else [f"{record['stage']}: engineer usefulness gate failed."]


def stage_permissions(stage, capability_ids):
    """Describe a ceiling; actual tool APIs must enforce scope and authorization."""
    level = {"shadow": 1, "recommend": 2, "prepare": 3,
             "limited_autonomy": 4, "production": 4}[stage]
    return {"maximum_level": level, "read_only_tools": True,
            "engineer_visible": stage != "shadow", "create_git_pr": level >= 3,
            "submit_preapproved_gitops": level >= 4,
            "direct_production_mutation": False, "broader_remediation_level_5": False,
            "capability_ids": capability_ids if level >= 4 else []}


def review_rollout(context, request, replay):
    """Review exactly one promotion while preserving all earlier stage evidence."""
    _validate_context(context)
    object_fields(request, {"release", "from_stage", "to_stage", "services", "environment",
                            "traffic_percent", "history"}, "rollout request")
    _release(request["release"])
    for key in ("from_stage", "to_stage"):
        _stage(request[key])
    identifiers(request["services"], "services")
    identifier(request["environment"], "request environment")
    number(request["traffic_percent"], "traffic_percent", 0.01, 100)
    _validate_history(request["history"])
    report, reasons = _replay_findings(context, replay)
    current, target = STAGES.index(request["from_stage"]), STAGES.index(request["to_stage"])
    if target != current + 1:
        reasons.append("Only the next rollout stage may be requested.")
    if request["from_stage"] != context["current_stage"]:
        reasons.append("Requested starting stage differs from the platform's current stage.")
    if request["release"] != context["release"]:
        reasons.append("Requested release differs from platform-approved release.")
    if (not request["services"] or not set(request["services"]).issubset(context["services"])
            or request["environment"] != context["environment"]):
        reasons.append("Requested scope is outside the authorized service/environment boundary.")
    if target and request["traffic_percent"] > context["maximum_traffic_percent"][STAGES[target]]:
        reasons.append("Requested traffic exceeds the stage limit.")
    expected = list(STAGES[1:current + 1])
    if [record["stage"] for record in request["history"]] != expected:
        reasons.append("Every completed stage must have exactly one ordered evidence record.")
    else:
        for record in request["history"]:
            reasons.extend(_observation_findings(context, request, record))
    if target >= STAGES.index("limited_autonomy") and not context["capability_ids"]:
        reasons.append("Autonomy requires at least one externally approved capability.")
    return {"decision": "block" if reasons else "eligible_for_next_stage", "reasons": reasons,
            "release": context["release"], "from_stage": request["from_stage"],
            "to_stage": request["to_stage"], "services": request["services"],
            "environment": request["environment"], "traffic_percent": request["traffic_percent"],
            "permissions": None if reasons else stage_permissions(
                request["to_stage"], context["capability_ids"]),
            "offline_decision": report["decision"],
            "input_sha256": {"context": fingerprint(context), "request": fingerprint(request),
                             "replay": fingerprint(replay)}}
