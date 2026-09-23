"""Exercise safety boundaries with untrusted intent and complete plan diffs."""

from copy import deepcopy
import json
from pathlib import Path
import unittest

from incident_copilot.models import ValidationError
from incident_copilot.remediation import evaluate_remediation


EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "remediation"


def fixture(name):
    """Load a standalone, runnable example."""
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


class RemediationTests(unittest.TestCase):
    """Reject bypasses and only route completely checked proposals to approval."""

    def setUp(self):
        self.intent = fixture("hpa_intent.json")
        self.context = fixture("reviewed_hpa_context.json")
        self.plan = fixture("hpa_plan.json")

    def evaluate(self):
        """Evaluate the per-test proposal."""
        return evaluate_remediation(self.intent, self.context, self.plan)

    def test_reviewed_limit_change_requires_senior_approval(self):
        """Reviewed limit change requires senior approval."""
        result = self.evaluate()
        self.assertEqual(result.decision, "requires_human_approval")
        self.assertEqual(result.approval, "senior")

    def test_hpa_is_evidence_not_an_obstacle(self):
        """Hpa is evidence not an obstacle."""
        result = evaluate_remediation(fixture("payments_scale_intent.json"), self.context)
        self.assertEqual(result.decision, "investigate")
        self.assertTrue(any("HPA" in reason for reason in result.reasons))
        self.assertIsNone(result.proposed_change)

    def test_conflicting_replicas_require_investigation(self):
        """Conflicting replicas require investigation."""
        self.context["current_state"]["replicas"] = 8
        self.assertEqual(self.evaluate().decision, "investigate")

    def test_existing_limit_requires_review(self):
        """Existing limit requires review."""
        del self.context["checks"]["existing_limit_reviewed"]
        self.assertEqual(self.evaluate().decision, "investigate")

    def test_unsafe_bounds_and_db_utilization_deny(self):
        """Unsafe bounds and db utilization deny."""
        for change in ({"db_utilization": 0.81}, {"max_blast_radius": 1, "blast_radius": 2},
                       {"approved_bounds": {"hpa.maxReplicas": 19}}):
            with self.subTest(change=change):
                self.context = fixture("reviewed_hpa_context.json")
                self.context.update(change)
                self.assertEqual(self.evaluate().decision, "deny")

    def test_excessive_scaling_denied(self):
        """Excessive scaling denied."""
        self.intent["desired_state"] = {"hpa.maxReplicas": 50}
        self.context["approved_bounds"]["hpa.maxReplicas"] = 100
        self.assertEqual(self.evaluate().decision, "deny")

    def test_missing_plan_cannot_reach_approval(self):
        """Missing plan cannot reach approval."""
        result = evaluate_remediation(self.intent, self.context)
        self.assertEqual(result.decision, "requires_plan")
        self.assertIsNone(result.approval)

    def test_unexpected_changes_denied(self):
        """Unexpected changes denied."""
        self.plan = fixture("unexpected_plan.json")
        self.assertEqual(self.evaluate().decision, "deny")

    def test_plan_identity_values_operation_and_completeness(self):
        """Plan identity values operation and completeness."""
        for key, value in {"resource": "other", "namespace": "dev", "environment": "dev",
                           "path": "other.tf", "controller": "terraform", "before": 9,
                           "after": 21, "field": "serviceAccount", "operation": "replace"}.items():
            with self.subTest(key=key):
                self.plan = fixture("hpa_plan.json")
                self.plan["changes"][0][key] = value
                self.assertEqual(self.evaluate().decision, "deny")
        for changes in ([], self.plan["changes"] * 2):
            self.plan = {"changes": changes}
            self.assertEqual(self.evaluate().decision, "deny")

    def test_target_and_rollback_are_bound_to_context(self):
        """Target and rollback are bound to context."""
        self.intent["environment"] = "dev"
        self.assertEqual(self.evaluate().decision, "deny")
        self.intent = fixture("hpa_intent.json")
        self.intent["rollback_plan"]["hpa.maxReplicas"] = 9
        self.assertEqual(self.evaluate().decision, "deny")

    def test_low_confidence(self):
        """Low confidence."""
        self.intent["confidence"] = 0.79
        self.assertEqual(self.evaluate().decision, "investigate")

    def test_malformed_untrusted_input_is_rejected(self):
        """Malformed untrusted input is rejected."""
        for change in ({"action": "DELETE"}, {"action": []}, {"confidence": True},
                       {"confidence": float("nan")}, {"confidence": float("inf")},
                       {"desired_state": {"hpa.maxReplicas": True}},
                       {"desired_state": {"hpa.maxReplicas": 20, "replicas": 20}},
                       {"resource": "../other"}, {"approved": True}, {"evidence": []}):
            with self.subTest(change=change):
                raw = dict(self.intent, **change)
                with self.assertRaises(ValidationError):
                    evaluate_remediation(raw, self.context, self.plan)
        for raw in (None, [], {}, "intent"):
            with self.assertRaises(ValidationError):
                evaluate_remediation(raw, self.context, self.plan)

    def test_malformed_trusted_facts_are_rejected(self):
        """Malformed trusted facts are rejected."""
        for key, value in {"db_utilization": float("nan"), "checks": {"quota": "yes"},
                           "observed_replicas": True, "git_path": "../outside",
                           "approved_bounds": {"replicas": False}}.items():
            with self.subTest(key=key), self.assertRaises(ValidationError):
                evaluate_remediation(self.intent, dict(self.context, **{key: value}), self.plan)

    def test_memory_checks_are_required_independently(self):
        """Memory checks are required independently."""
        self.intent["desired_state"] = {"memory.limitMi": 1024}
        self.intent["rollback_plan"] = {"memory.limitMi": 512}
        self.context["current_state"]["memory.limitMi"] = 512
        self.context["approved_bounds"]["memory.limitMi"] = 1024
        checks = ["memory_saturation", "oomkills_observed", "leak_ruled_out",
                  "capacity_available", "quota_available", "cost_reviewed",
                  "existing_limit_reviewed", "memory_request_reviewed"]
        self.context["checks"].update(dict.fromkeys(checks, True))
        self.plan["changes"][0].update(field="memory.limitMi", before=512, after=1024)
        self.assertEqual(self.evaluate().decision, "requires_human_approval")
        for check in checks:
            with self.subTest(check=check):
                context = deepcopy(self.context)
                context["checks"][check] = False
                self.assertEqual(evaluate_remediation(self.intent, context, self.plan).decision,
                                 "investigate")

    def test_infrastructure_plan_and_known_good_rollback(self):
        """Infrastructure plan and known good rollback."""
        self.context["controller"] = "terraform"
        self.context["current_state"]["node_pool.max_nodes"] = 6
        self.context["approved_bounds"]["node_pool.max_nodes"] = 10
        self.context["checks"]["pending_pods_insufficient_cpu"] = True
        self.intent["desired_state"] = {"node_pool.max_nodes": 10}
        self.intent["rollback_plan"] = {"node_pool.max_nodes": 6}
        self.plan["changes"][0].update(controller="terraform", field="node_pool.max_nodes",
                                       before=6, after=10)
        self.assertEqual(self.evaluate().decision, "requires_human_approval")
        self.intent.update(action="ROLLBACK", desired_state={"image.tag": "v2.19"},
                           rollback_plan={"image.tag": "v2.20"})
        self.context["current_state"]["image.tag"] = "v2.20"
        self.context["known_good_version"] = "v2.18"
        self.assertEqual(self.evaluate().decision, "deny")
        self.context["known_good_version"] = "v2.19"
        self.context["checks"].update(regression_evidence=True, dependencies_healthy=True)
        self.plan["changes"][0].update(field="image.tag", before="v2.20", after="v2.19")
        self.assertEqual(self.evaluate().decision, "requires_human_approval")

    def test_scale_within_hpa_requires_operator_approval(self):
        """Scale within hpa requires operator approval."""
        self.intent = fixture("payments_scale_intent.json")
        self.context["hpa_max_replicas"] = 20
        self.context["current_state"]["hpa.maxReplicas"] = 20
        self.plan["changes"][0].update(field="replicas", before=10, after=16)
        result = self.evaluate()
        self.assertEqual(result.decision, "requires_human_approval")
        self.assertEqual(result.approval, "operator")


if __name__ == "__main__":
    unittest.main()
