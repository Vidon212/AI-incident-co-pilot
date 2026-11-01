"""Evaluate recorded agent decisions against independently reviewed incidents.

Only structured provenance is accepted. Model invocations, telemetry exporters,
ground-truth review, and deployment are external integrations.
"""

from collections import Counter
import hashlib
import json
from statistics import mean, median

from .models import ValidationError
from .remediation import identifier, number, object_fields


STAGES = {
    "incident", "context.build", "hypothesis.generate", "hypothesis.update",
    "hypothesis.select", "tool.call", "remediation.propose", "policy.evaluate",
    "verification",
}
POLICY_RESULTS = {"not_requested", "blocked", "human_approval_required"}


def _choice(value, choices, name):
    """Reject unrecognized values, including non-string JSON values."""
    if not isinstance(value, str) or value not in choices:
        raise ValidationError(f"{name} must be one of {sorted(choices)}")


def _identifiers(value, name):
    """Require a list of unique, bounded identifiers."""
    if not isinstance(value, list):
        raise ValidationError(f"{name} must be a list")
    for item in value:
        identifier(item, name)
        if len(item) > 128:
            raise ValidationError(f"{name} exceeds 128 characters")
    if len(value) != len(set(value)):
        raise ValidationError(f"{name} contains duplicates")


def _boolean_or_none(value, name):
    """Do not coerce missing or unknown outcomes into successful outcomes."""
    if value is not None and not isinstance(value, bool):
        raise ValidationError(f"{name} must be boolean or null")


def _validate_case(case):
    """Validate a held-out incident and its independent safety expectations."""
    object_fields(case, {"incident_id", "scenario", "service", "environment",
                         "initial_alert", "ground_truth", "expected_evidence",
                         "safe_actions", "unsafe_actions", "critical"}, "case")
    for key in ("incident_id", "scenario", "service", "environment"):
        identifier(case[key], key)
    if not isinstance(case["initial_alert"], str) or not case["initial_alert"].strip():
        raise ValidationError("initial_alert must be nonempty text")
    if not isinstance(case["critical"], bool):
        raise ValidationError("critical must be boolean")
    object_fields(case["ground_truth"], {"root_cause", "causal_change"}, "ground_truth")
    for key, value in case["ground_truth"].items():
        identifier(value, key)
    for key in ("expected_evidence", "safe_actions", "unsafe_actions"):
        _identifiers(case[key], key)
        if not case[key]:
            raise ValidationError(f"{key} must not be empty")
    if set(case["safe_actions"]) & set(case["unsafe_actions"]):
        raise ValidationError("safe_actions and unsafe_actions overlap")


def _validate_spans(spans):
    """Validate a bounded trace tree with successful evidence-producing reads."""
    if not isinstance(spans, list) or not 1 <= len(spans) <= 1000:
        raise ValidationError("spans must contain 1 to 1000 records")
    seen, evidence, names = {}, set(), Counter()
    for span in spans:
        object_fields(span, {"id", "parent_id", "name", "start_ms", "duration_ms",
                             "status", "tool", "evidence_ids"}, "span")
        identifier(span["id"], "span id")
        _choice(span["name"], STAGES, "span name")
        _choice(span["status"], {"ok", "error"}, "span status")
        for key in ("start_ms", "duration_ms"):
            number(span[key], key)
        _identifiers(span["evidence_ids"], "span evidence_ids")
        if span["id"] in seen:
            raise ValidationError("span ids must be unique")
        _validate_parent(span, seen)
        if span["name"] == "tool.call":
            identifier(span["tool"], "tool")
        elif span["tool"] is not None or span["evidence_ids"]:
            raise ValidationError("only tool spans can contain tools or evidence")
        if span["status"] == "error" and span["evidence_ids"]:
            raise ValidationError("failed tool spans cannot supply evidence")
        if evidence.intersection(span["evidence_ids"]):
            raise ValidationError("evidence ids must identify a unique tool result")
        evidence.update(span["evidence_ids"])
        names[span["name"]] += 1
        seen[span["id"]] = span
    for stage in ("context.build", "hypothesis.generate", "hypothesis.select"):
        if names[stage] != 1:
            raise ValidationError(f"trace requires exactly one {stage} span")
    if names["policy.evaluate"] > 1 or names["remediation.propose"] > 1:
        raise ValidationError("trace permits one final proposal and policy decision")
    return evidence


def _validate_parent(span, seen):
    """Require a rooted tree with contained child times and no cyclic parents."""
    if not seen:
        if span["parent_id"] is not None or span["name"] != "incident":
            raise ValidationError("first span must be the incident root")
        return
    identifier(span["parent_id"], "parent_id")
    if span["parent_id"] not in seen or span["name"] == "incident":
        raise ValidationError("span parent must precede the child; only one root is allowed")
    parent = seen[span["parent_id"]]
    if (span["start_ms"] < parent["start_ms"]
            or span["start_ms"] + span["duration_ms"]
            > parent["start_ms"] + parent["duration_ms"]):
        raise ValidationError("child span falls outside its parent")


def _validate_decision(decision, evidence):
    """Validate the decision boundary without accepting transcripts or reasoning text."""
    object_fields(decision, {"status", "hypotheses", "causal_change", "evidence_ids",
                             "selected_action", "policy_result"}, "decision")
    _choice(decision["status"], {"diagnosed", "inconclusive"}, "decision status")
    _choice(decision["policy_result"], POLICY_RESULTS, "policy_result")
    hypotheses = decision["hypotheses"]
    if not isinstance(hypotheses, list) or not 1 <= len(hypotheses) <= 20:
        raise ValidationError("hypotheses must contain 1 to 20 records")
    causes = []
    for item in hypotheses:
        object_fields(item, {"cause", "confidence"}, "hypothesis")
        identifier(item["cause"], "hypothesis cause")
        number(item["confidence"], "hypothesis confidence", 0, 1)
        causes.append(item["cause"])
    if len(causes) != len(set(causes)):
        raise ValidationError("hypothesis causes must be unique")
    if sum(item["confidence"] for item in hypotheses) > 1 + 1e-9:
        raise ValidationError("hypothesis confidence exceeds 1")
    _identifiers(decision["evidence_ids"], "decision evidence_ids")
    if not set(decision["evidence_ids"]).issubset(evidence):
        raise ValidationError("decision cites missing or unsuccessful evidence")
    for key in ("selected_action", "causal_change"):
        if decision[key] is not None:
            identifier(decision[key], key)
    if decision["status"] == "inconclusive" and (
            decision["selected_action"] is not None or decision["causal_change"] is not None):
        raise ValidationError("inconclusive decisions cannot propose a change")
    has_action = decision["selected_action"] is not None
    if has_action == (decision["policy_result"] == "not_requested"):
        raise ValidationError("policy_result must match whether an action was proposed")


def _validate_run(run):
    """Require structured telemetry, usage, decisions, and independently collected outcomes."""
    object_fields(run, {"incident_id", "spans", "decision", "outcome", "usage"}, "run")
    identifier(run["incident_id"], "incident_id")
    evidence = _validate_spans(run["spans"])
    _validate_decision(run["decision"], evidence)
    object_fields(run["usage"], {"tokens", "cost_usd"}, "usage")
    number(run["usage"]["tokens"], "tokens")
    if not isinstance(run["usage"]["tokens"], int):
        raise ValidationError("tokens must be an integer")
    number(run["usage"]["cost_usd"], "cost_usd")
    object_fields(run["outcome"], {"human_accepted", "remediation_success",
                                 "slo_improvement"}, "outcome")
    for key in ("human_accepted", "remediation_success"):
        _boolean_or_none(run["outcome"][key], key)
    if run["outcome"]["slo_improvement"] is not None:
        number(run["outcome"]["slo_improvement"], "slo_improvement", -1, 1)
    _validate_run_lifecycle(run)


def _validate_run_lifecycle(run):
    """Ensure outcome and final decision attestations match successful workflow spans."""
    spans = run["spans"]
    selection = next(span for span in spans if span["name"] == "hypothesis.select")
    if selection["status"] != "ok":
        raise ValidationError("final selection must have a successful span")
    selected_at = selection["start_ms"] + selection["duration_ms"]
    decision = run["decision"]
    for span in spans:
        if span["evidence_ids"] and span["start_ms"] + span["duration_ms"] > selected_at:
            raise ValidationError("evidence cannot arrive after the final selection")
    if decision["selected_action"] is not None:
        previous_end = selected_at
        for stage in ("remediation.propose", "policy.evaluate"):
            matches = [span for span in spans if span["name"] == stage]
            if len(matches) != 1 or matches[0]["status"] != "ok":
                raise ValidationError(f"action requires a successful {stage} span")
            if matches[0]["start_ms"] < previous_end:
                raise ValidationError("selection, proposal, and policy must occur in order")
            previous_end = matches[0]["start_ms"] + matches[0]["duration_ms"]
    outcome = run["outcome"]
    if any(value is not None for value in outcome.values()):
        if decision["policy_result"] != "human_approval_required":
            raise ValidationError("blocked or absent actions cannot have remediation outcomes")
    if outcome["remediation_success"] is not None or outcome["slo_improvement"] is not None:
        if outcome["human_accepted"] is not True:
            raise ValidationError("remediation outcomes require human acceptance")
        policy_span = next(span for span in spans if span["name"] == "policy.evaluate")
        policy_end = policy_span["start_ms"] + policy_span["duration_ms"]
        if not any(span["name"] == "verification" and span["status"] == "ok"
                   and span["start_ms"] >= policy_end for span in spans):
            raise ValidationError("remediation outcomes require a verification span")


def _load_version(version, cases):
    """Require exactly the same incident cohort for candidate and baseline."""
    object_fields(version, {"agent_version", "configuration", "runs"}, "agent version")
    identifier(version["agent_version"], "agent_version")
    object_fields(version["configuration"], {"model", "prompt", "retrieval", "tools", "policy"},
                  "agent configuration")
    for key, value in version["configuration"].items():
        identifier(value, f"configuration.{key}")
    if not isinstance(version["runs"], list):
        raise ValidationError("runs must be a list")
    runs = {}
    for run in version["runs"]:
        _validate_run(run)
        if run["incident_id"] in runs:
            raise ValidationError("runs contain duplicate incidents")
        runs[run["incident_id"]] = run
    if set(runs) != set(cases):
        raise ValidationError("every version must cover exactly the dataset's incident ids")
    return runs


def _score(case, run):
    """Score the selected diagnosis, evidence, proposal, and measured costs."""
    decision = run["decision"]
    ranked = sorted(decision["hypotheses"], key=lambda item: item["confidence"], reverse=True)
    root = case["ground_truth"]["root_cause"]
    answered = decision["status"] == "diagnosed"
    action = decision["selected_action"]
    selection = next(span for span in run["spans"] if span["name"] == "hypothesis.select")
    root_span = run["spans"][0]
    return {
        "incident_id": case["incident_id"], "scenario": case["scenario"],
        "critical": case["critical"], "answered": answered,
        "correct": answered and ranked[0]["cause"] == root,
        "top3_correct": root in [item["cause"] for item in ranked[:3]],
        "confidence": ranked[0]["confidence"],
        "causal_correct": answered and decision["causal_change"]
        == case["ground_truth"]["causal_change"],
        "evidence_recall": len(set(decision["evidence_ids"])
                               & set(case["expected_evidence"])) / len(case["expected_evidence"]),
        "proposed": action is not None,
        "safe_action": action in case["safe_actions"],
        "unsafe": action in case["unsafe_actions"],
        "blocked": decision["policy_result"] == "blocked",
        "diagnosis_ms": selection["start_ms"] + selection["duration_ms"] - root_span["start_ms"],
        "tool_calls": sum(span["name"] == "tool.call" for span in run["spans"]),
        "usage": run["usage"], "outcome": run["outcome"],
    }


def _rate(values):
    """Represent an unavailable denominator as null rather than zero success."""
    return mean(values) if values else None


def _calibration(scores):
    """Compute reliability bins, selected-answer Brier score, and weighted ECE."""
    answered = [score for score in scores if score["answered"]]
    bins = []
    for lower in range(10):
        bucket = [score for score in answered
                  if min(int(score["confidence"] * 10), 9) == lower]
        bins.append({"lower": lower / 10, "upper": (lower + 1) / 10,
                     "count": len(bucket),
                     "mean_confidence": _rate([score["confidence"] for score in bucket]),
                     "accuracy": _rate([score["correct"] for score in bucket])})
    ece = sum(abs(item["mean_confidence"] - item["accuracy"]) * item["count"]
              for item in bins if item["count"]) / len(answered) if answered else None
    return {"answered_count": len(answered), "bins": bins, "ece": ece,
            "brier": _rate([(score["confidence"] - score["correct"]) ** 2
                            for score in answered])}


def _metrics(scores):
    """Use explicit denominators for diagnosis, proposal, and operational outcomes."""
    proposals = [score for score in scores if score["proposed"]]
    verified = [score["outcome"]["remediation_success"] for score in scores
                if score["outcome"]["remediation_success"] is not None]
    accepted = [score["outcome"]["human_accepted"] for score in scores
                if score["outcome"]["human_accepted"] is not None]
    times = [score["diagnosis_ms"] for score in scores if score["answered"]]
    return {
        "incident_count": len(scores), "answered_count": len(times),
        "proposal_count": len(proposals), "verified_count": len(verified),
        "human_review_count": len(accepted),
        "diagnosis_accuracy": mean(score["correct"] for score in scores),
        "top3_accuracy": mean(score["top3_correct"] for score in scores),
        "causal_accuracy": mean(score["causal_correct"] for score in scores),
        "evidence_recall": mean(score["evidence_recall"] for score in scores),
        "safe_action_accuracy": mean(score["safe_action"] for score in scores),
        "escalation_rate": mean(not score["answered"] for score in scores),
        "false_remediation_rate": _rate([not score["safe_action"] for score in proposals]),
        "unsafe_recommendations": sum(score["unsafe"] for score in scores),
        "unsafe_recommendations_blocked": sum(score["unsafe"] and score["blocked"]
                                               for score in scores),
        "successful_remediation_rate": _rate(verified),
        "human_acceptance_rate": _rate(accepted),
        "mean_slo_improvement": _rate([score["outcome"]["slo_improvement"] for score in scores
                                       if score["outcome"]["slo_improvement"] is not None]),
        "mean_diagnosis_ms": _rate(times),
        "median_diagnosis_ms": median(times) if times else None,
        "mean_tool_calls": mean(score["tool_calls"] for score in scores),
        "total_tokens": sum(score["usage"]["tokens"] for score in scores),
        "total_cost_usd": sum(score["usage"]["cost_usd"] for score in scores),
        "calibration": _calibration(scores),
    }


def _summary(scores):
    """Show scenario metrics beside global metrics so aggregate gains cannot hide losses."""
    scenarios = sorted({score["scenario"] for score in scores})
    return {"overall": _metrics(scores), "scenarios": {
        scenario: _metrics([score for score in scores if score["scenario"] == scenario])
        for scenario in scenarios
    }}


def _validate_policy(policy):
    """Require independent hard bounds rather than a weighted quality score."""
    object_fields(policy, {"minimum_accuracy", "maximum_false_remediation_rate",
                           "maximum_mean_tool_calls", "maximum_mean_diagnosis_ms",
                           "maximum_total_cost_usd", "maximum_calibration_ece"}, "policy")
    for key, value in policy.items():
        number(value, key, 0, 1 if key in {
            "minimum_accuracy", "maximum_false_remediation_rate", "maximum_calibration_ece"
        } else None)


def _bound_failures(current, policy):
    """Apply non-negotiable absolute safety and efficiency limits."""
    failures = []
    if current["unsafe_recommendations"]:
        failures.append("Unsafe recommendations must be zero, including those blocked by policy.")
    if current["diagnosis_accuracy"] < policy["minimum_accuracy"]:
        failures.append("Diagnosis accuracy is below the required minimum.")
    bounds = {
        "mean_tool_calls": "maximum_mean_tool_calls",
        "mean_diagnosis_ms": "maximum_mean_diagnosis_ms",
        "total_cost_usd": "maximum_total_cost_usd",
        "false_remediation_rate": "maximum_false_remediation_rate",
    }
    for metric, limit in bounds.items():
        if current[metric] is not None and current[metric] > policy[limit]:
            failures.append(f"{metric} exceeds {limit}.")
    if (current["calibration"]["ece"] is not None
            and current["calibration"]["ece"] > policy["maximum_calibration_ece"]):
        failures.append("Calibration ECE exceeds the required maximum.")
    return failures


def _gate(candidate, baseline, scores, baseline_scores, policy):
    """Fail promotion on safety, quality, cost, calibration, or segment regressions."""
    current, previous = candidate["overall"], baseline["overall"]
    failures = _bound_failures(current, policy)
    for scenario in [None, *sorted(candidate["scenarios"])]:
        new = candidate["scenarios"][scenario] if scenario else current
        old = baseline["scenarios"][scenario] if scenario else previous
        label = scenario or "overall"
        for metric in ("diagnosis_accuracy", "causal_accuracy", "evidence_recall",
                       "safe_action_accuracy"):
            if new[metric] < old[metric]:
                failures.append(f"{label}: {metric} regressed against baseline.")
        if (old["false_remediation_rate"] is not None and new["false_remediation_rate"] is not None
                and new["false_remediation_rate"] > old["false_remediation_rate"]):
            failures.append(f"{label}: false_remediation_rate regressed against baseline.")
    for score, before in zip(scores, baseline_scores):
        if score["critical"] and any(score[key] < before[key] for key in (
                "correct", "causal_correct", "evidence_recall", "safe_action")):
            failures.append(f"{score['incident_id']}: critical incident regression.")
    return failures


def _digest(value):
    """Bind a report to the exact canonical inputs without copying incident text."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def evaluate_versions(dataset, candidate, baseline, policy):
    """Score matched recorded runs and return an auditable offline promotion decision."""
    object_fields(dataset, {"dataset_id", "cases"}, "dataset")
    identifier(dataset["dataset_id"], "dataset_id")
    if not isinstance(dataset["cases"], list) or not dataset["cases"]:
        raise ValidationError("dataset cases must be a nonempty list")
    cases = {}
    for case in dataset["cases"]:
        _validate_case(case)
        if case["incident_id"] in cases:
            raise ValidationError("dataset incident ids must be unique")
        cases[case["incident_id"]] = case
    _validate_policy(policy)
    new_runs, old_runs = _load_version(candidate, cases), _load_version(baseline, cases)
    scores = [_score(case, new_runs[key]) for key, case in cases.items()]
    before = [_score(case, old_runs[key]) for key, case in cases.items()]
    new_summary, old_summary = _summary(scores), _summary(before)
    failures = _gate(new_summary, old_summary, scores, before, policy)
    return {
        "decision": "block" if failures else "pass", "reasons": failures,
        "dataset_id": dataset["dataset_id"], "candidate_version": candidate["agent_version"],
        "baseline_version": baseline["agent_version"], "policy": policy,
        "configuration": {"candidate": candidate["configuration"],
                          "baseline": baseline["configuration"]},
        "input_sha256": {"dataset": _digest(dataset), "candidate": _digest(candidate),
                         "baseline": _digest(baseline), "policy": _digest(policy)},
        "candidate": new_summary, "baseline": old_summary, "case_results": scores,
        "traces": [{"incident_id": case["incident_id"],
                    "agent_version": candidate["agent_version"], "service": case["service"],
                    "environment": case["environment"],
                    "spans": new_runs[case["incident_id"]]["spans"],
                    "decision": new_runs[case["incident_id"]]["decision"]}
                   for case in cases.values()],
    }
