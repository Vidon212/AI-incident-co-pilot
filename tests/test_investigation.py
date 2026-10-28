"""Verify multi-hypothesis investigation and deterministic stopping rules."""

from copy import deepcopy
import json
from pathlib import Path
import unittest

from incident_copilot.investigation import evaluate_investigation
from incident_copilot.models import ValidationError


ROOT = Path(__file__).parents[1]


def fixture(name):
    """Load one published Stage 8 example."""
    with (ROOT / "examples" / "investigation" / name).open(encoding="utf-8") as source:
        return json.load(source)


class MultiHypothesisInvestigationTests(unittest.TestCase):
    """Exercise hypotheses, evidence, falsification, and stop policy."""

    def setUp(self):
        """Load the synthetic checkout investigation."""
        self.context = fixture("checkout-incident-context.json")
        self.run = fixture("checkout-investigation-run.json")

    def evaluate(self):
        """Evaluate the current mutable test fixtures."""
        return evaluate_investigation(self.context, self.run)

    def test_causal_investigation_is_ready_for_remediation_review(self):
        """Independent causal evidence can cross the configured stop threshold."""
        result = self.evaluate()
        self.assertEqual(result.decision, "ready_for_remediation_review")
        self.assertEqual(result.primary_hypothesis["id"], "H2")
        self.assertEqual(result.primary_hypothesis["confidence"], 0.94)
        self.assertEqual(result.hypotheses[0]["id"], "H2")
        self.assertEqual(result.recommended_action["to"], 500)
        self.assertEqual(len(result.audit), 4)

    def test_requires_competing_normalized_hypotheses(self):
        """A single favored explanation cannot enter the investigation loop."""
        self.run["hypotheses"] = self.run["hypotheses"][:2]
        with self.assertRaises(ValidationError):
            self.evaluate()
        self.run = fixture("checkout-investigation-run.json")
        self.run["hypotheses"][0]["confidence"] = 0.5
        with self.assertRaises(ValidationError):
            self.evaluate()

    def test_confidence_updates_must_form_a_complete_chain(self):
        """Evidence cannot skip a hypothesis or rewrite its previous confidence."""
        self.run["evidence"][1]["hypothesis_updates"][0]["before"] = 0.35
        with self.assertRaises(ValidationError):
            self.evaluate()
        self.run = fixture("checkout-investigation-run.json")
        self.run["final_assessment"]["confidence"] = 0.95
        with self.assertRaises(ValidationError):
            self.evaluate()

    def test_evidence_must_discriminate_between_hypotheses(self):
        """A tool call needs a stated choice it can help resolve."""
        self.run["evidence"][0]["discriminates"] = ["H1"]
        with self.assertRaises(ValidationError):
            self.evaluate()

    def test_primary_hypothesis_must_survive_falsification(self):
        """High confidence alone does not satisfy the stopping rule."""
        self.run["evidence"][-1]["falsification_target"] = None
        result = self.evaluate()
        self.assertEqual(result.decision, "inconclusive")
        self.assertTrue(any("falsification" in reason for reason in result.reasons))

    def test_similar_version_health_weakens_deployment_anchoring(self):
        """A materially healthier old version would keep the app regression open."""
        version = self.run["evidence"][0]["result"]["data"]["versions"][0]
        version["http_5xx_rate"] = 0.01
        version["p99_latency_ms"] = 500
        self.assertEqual(self.evaluate().decision, "inconclusive")

    def test_database_evidence_must_show_connection_exhaustion(self):
        """Normal pool use cannot support a connection exhaustion conclusion."""
        data = self.run["evidence"][1]["result"]["data"]
        data["connections_used"] = 100
        data["connection_wait_ms"] = 50
        self.assertEqual(self.evaluate().decision, "inconclusive")

    def test_timeline_must_link_prior_demand_to_post_change_errors(self):
        """Correlation without the expected temporal sequence stays inconclusive."""
        samples = self.run["evidence"][-1]["result"]["data"]["samples"]
        samples[0]["connections_used"] = 200
        samples[1]["connections_used"] = 220
        self.assertEqual(self.evaluate().decision, "inconclusive")

    def test_causal_change_is_bound_to_the_change_record(self):
        """The final answer cannot invent a different rollback value."""
        assessment = self.run["final_assessment"]
        assessment["causal_change"]["before"] = 600
        assessment["recommended_action"]["to"] = 600
        result = self.evaluate()
        self.assertEqual(result.decision, "inconclusive")
        self.assertTrue(any("change record" in reason for reason in result.reasons))

    def test_budget_exhaustion_returns_inconclusive(self):
        """Time and tool ceilings stop investigation rather than force an answer."""
        context = deepcopy(self.context)
        context["budget"]["max_tool_calls"] = 3
        result = evaluate_investigation(context, self.run)
        self.assertEqual(result.decision, "inconclusive")
        self.assertEqual(result.recommended_action, {"action": "escalate"})
        self.assertEqual(result.hypotheses[0]["id"], "H2")
        self.assertTrue(any("tool-call budget" in reason for reason in result.reasons))
        self.run["elapsed_seconds"] = 301
        self.assertEqual(self.evaluate().decision, "inconclusive")

    def test_budget_expiry_without_a_final_answer_preserves_top_hypotheses(self):
        """An unavailable source ends in escalation without a fabricated cause."""
        self.run["evidence"] = self.run["evidence"][:1]
        self.run["elapsed_seconds"] = 300
        self.run["final_assessment"] = None
        result = self.evaluate()
        self.assertEqual(result.decision, "inconclusive")
        self.assertEqual(result.hypotheses[0]["id"], "H2")
        self.assertIsNone(result.primary_hypothesis)
        self.assertEqual(result.recommended_action, {"action": "escalate"})
        self.assertTrue(any("budget expired" in reason for reason in result.reasons))

    def test_final_answer_requires_independent_cited_sources(self):
        """Uncited reads do not satisfy the independent evidence threshold."""
        self.run["final_assessment"]["supporting_evidence_call_ids"] = [
            "checkout-versions", "checkout-database"
        ]
        self.assertEqual(self.evaluate().decision, "inconclusive")

    def test_scope_result_identity_and_verification_are_strict(self):
        """Malformed provenance, cross-scope data, and empty checks are rejected."""
        cases = []
        run = deepcopy(self.run)
        run["evidence"][0]["result"]["call_id"] = "other-call"
        cases.append(run)
        run = deepcopy(self.run)
        run["evidence"][1]["call"]["arguments"]["resource"] = "other-prod"
        cases.append(run)
        run = deepcopy(self.run)
        run["final_assessment"]["verification_criteria"] = []
        cases.append(run)
        for run in cases:
            with self.subTest(run=run), self.assertRaises(ValidationError):
                evaluate_investigation(self.context, run)


if __name__ == "__main__":
    unittest.main()
