"""Verify bounded tool use, evidence binding, and intent-to-plan safety."""

from copy import deepcopy
import json
from pathlib import Path
import unittest

from incident_copilot.agent import evaluate_agent_run
from incident_copilot.models import ValidationError


ROOT = Path(__file__).parents[1]


def fixture(name):
    """Load one published Stage 7 example."""
    with (ROOT / "examples" / "agent" / name).open(encoding="utf-8") as source:
        return json.load(source)


class AgentToolPolicyTests(unittest.TestCase):
    """Exercise the tool gateway, investigation loop, and proposal policy."""

    def setUp(self):
        """Load the synthetic pricing incident."""
        self.context = fixture("pricing-incident-context.json")
        self.run = fixture("pricing-investigation-run.json")
        self.plan = fixture("pricing-terraform-plan.json")

    def evaluate(self, plan=True):
        """Evaluate the current fixtures with or without a plan."""
        return evaluate_agent_run(self.context, self.run, self.plan if plan else None)

    def test_complete_investigation_and_exact_plan_require_approval(self):
        """Bound evidence and an exact plan produce a reviewable proposal."""
        result = self.evaluate()
        self.assertEqual(result.decision, "requires_human_approval")
        self.assertEqual(result.approval, "senior")
        self.assertEqual(result.proposed_change["before"], 300)
        self.assertEqual(result.proposed_change["after"], 500)
        self.assertEqual(len(result.audit), 6)

    def test_missing_plan_cannot_reach_approval(self):
        """An agent proposal remains incomplete until a trusted plan exists."""
        self.assertEqual(self.evaluate(plan=False).decision, "requires_plan")

    def test_unexpected_plan_change_is_denied(self):
        """A matching update cannot hide an additional deletion."""
        result = evaluate_agent_run(
            self.context, self.run, fixture("unexpected-terraform-plan.json")
        )
        self.assertEqual(result.decision, "deny")

    def test_arbitrary_raw_tool_is_denied(self):
        """Shell and infrastructure primitives are outside the tool catalog."""
        self.run["steps"][0]["call"]["tool"] = "kubectl"
        self.assertEqual(self.evaluate().decision, "deny")

    def test_service_and_environment_boundaries_are_enforced(self):
        """Tool calls cannot escape authenticated incident scope."""
        for key, value in (("service", "secrets-api"), ("environment", "staging")):
            with self.subTest(key=key):
                run = deepcopy(self.run)
                run["steps"][0]["call"]["arguments"][key] = value
                self.assertEqual(evaluate_agent_run(self.context, run, self.plan).decision,
                                 "deny")

    def test_loop_and_time_window_are_bounded(self):
        """The platform stops excessive steps and broad history queries."""
        context = deepcopy(self.context)
        context["limits"]["max_steps"] = 5
        self.assertEqual(evaluate_agent_run(context, self.run, self.plan).decision, "deny")
        run = deepcopy(self.run)
        run["steps"][3]["call"]["arguments"]["window_minutes"] = 31
        self.assertEqual(evaluate_agent_run(self.context, run, self.plan).decision, "deny")

    def test_log_queries_require_narrow_scope_and_redaction(self):
        """Broad log queries are denied and unredacted results are rejected."""
        run = deepcopy(self.run)
        step = run["steps"][0]
        step["call"].update(tool="get_logs", arguments={
            "service": "checkout-api", "environment": "production",
            "query": "*", "window_minutes": 30, "limit": 10,
        })
        self.assertEqual(evaluate_agent_run(self.context, run, self.plan).decision, "deny")
        step["call"]["arguments"]["query"] = "level=error"
        step["result"].update(
            source="logs", redaction_applied=False,
            data={"service": "checkout-api", "entries": ["database timeout"]},
        )
        with self.assertRaises(ValidationError):
            evaluate_agent_run(self.context, run, self.plan)

    def test_result_identity_size_and_proposal_execution_are_rejected(self):
        """Results stay bound, bounded, and unable to claim execution."""
        cases = []
        run = deepcopy(self.run)
        run["steps"][0]["result"]["call_id"] = "other-call"
        cases.append(run)
        run = deepcopy(self.run)
        run["steps"][0]["result"]["data"]["padding"] = "x" * 5000
        cases.append(run)
        run = deepcopy(self.run)
        run["steps"][-1]["result"]["data"]["proposal_only"] = False
        cases.append(run)
        for run in cases:
            with self.subTest(run=run), self.assertRaises(ValidationError):
                evaluate_agent_run(self.context, run, self.plan)

    def test_result_target_and_status_are_bound_to_calls(self):
        """A result from another target or capability cannot satisfy the trace."""
        cases = []
        run = deepcopy(self.run)
        run["steps"][0]["result"]["data"]["service"] = "pricing-api"
        cases.append(run)
        run = deepcopy(self.run)
        run["steps"][0]["result"]["status"] = "proposed"
        cases.append(run)
        run = deepcopy(self.run)
        run["steps"][-1]["result"]["status"] = "ok"
        cases.append(run)
        for run in cases:
            with self.subTest(run=run), self.assertRaises(ValidationError):
                evaluate_agent_run(self.context, run, self.plan)

    def test_proposal_values_require_health_and_change_evidence(self):
        """The model cannot invent current or rollback values in its proposal."""
        run = deepcopy(self.run)
        run["steps"][4]["result"]["data"]["connections_limit"] = 301
        self.assertEqual(evaluate_agent_run(self.context, run, self.plan).decision,
                         "investigate")
        run = deepcopy(self.run)
        run["steps"][3]["result"]["data"]["changes"][0]["before"] = 600
        self.assertEqual(evaluate_agent_run(self.context, run, self.plan).decision,
                         "investigate")

    def test_hypothesis_and_proposal_must_cite_successful_reads(self):
        """A model cannot invent evidence or change citations at the proposal step."""
        run = deepcopy(self.run)
        run["hypothesis"]["evidence_call_ids"].append("missing-call")
        self.assertEqual(evaluate_agent_run(self.context, run, self.plan).decision, "deny")
        run = deepcopy(self.run)
        run["steps"][-1]["call"]["arguments"]["evidence_call_ids"] = ["pricing-database"]
        self.assertEqual(evaluate_agent_run(self.context, run, self.plan).decision, "deny")

    def test_low_confidence_proposal_returns_to_investigation(self):
        """Urgency cannot substitute for sufficient evidence confidence."""
        self.run["hypothesis"]["confidence"] = 0.79
        self.assertEqual(self.evaluate().decision, "investigate")


if __name__ == "__main__":
    unittest.main()
