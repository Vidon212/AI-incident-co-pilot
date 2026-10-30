"""Check cohort integrity, provenance, metric denominators, and promotion constraints."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from incident_copilot.evaluation import evaluate_versions
from incident_copilot.models import ValidationError


ROOT = Path(__file__).parents[1]
EXAMPLES = ROOT / "examples" / "evaluation"


def fixture(name):
    """Load one versioned synthetic evaluation input."""
    return json.loads((EXAMPLES / f"{name}.json").read_text(encoding="utf-8"))


class EvaluationTests(unittest.TestCase):
    """Exercise quality and safety together, including incomplete agent outcomes."""

    def setUp(self):
        """Load independent dataset, baseline, candidate, and gate policy."""
        self.dataset = fixture("incidents")
        self.candidate = fixture("candidate")
        self.baseline = fixture("baseline")
        self.policy = fixture("promotion-policy")

    def evaluate(self):
        """Evaluate the current comparison."""
        return evaluate_versions(self.dataset, self.candidate, self.baseline, self.policy)

    def test_metrics_and_calibration_use_explicit_denominators(self):
        """Abstentions affect accuracy and coverage; unknown outcomes stay unknown."""
        report = self.evaluate()
        self.assertEqual(report["decision"], "pass")
        metrics = report["candidate"]["overall"]
        self.assertEqual(metrics["incident_count"], 5)
        self.assertAlmostEqual(metrics["diagnosis_accuracy"], 0.8)
        self.assertAlmostEqual(metrics["top3_accuracy"], 1)
        self.assertAlmostEqual(metrics["escalation_rate"], 0.2)
        self.assertEqual(metrics["mean_diagnosis_ms"], 125000)
        self.assertEqual(metrics["mean_tool_calls"], 3)
        self.assertAlmostEqual(metrics["total_cost_usd"], 0.105)
        self.assertEqual(metrics["verified_count"], 4)
        self.assertEqual(metrics["human_review_count"], 4)
        self.assertAlmostEqual(metrics["calibration"]["ece"], 0.06)
        self.assertAlmostEqual(metrics["calibration"]["brier"], 0.0036)
        self.assertEqual(report["candidate"]["scenarios"]["networking"]["verified_count"], 0)
        self.assertIsNone(report["candidate"]["scenarios"]["networking"]
                          ["successful_remediation_rate"])

    def test_policy_block_does_not_erase_an_unsafe_recommendation(self):
        """Even a safely blocked recommendation counts as unsafe agent behavior."""
        run = self.candidate["runs"][0]
        run["decision"]["selected_action"] = "delete_database"
        run["decision"]["policy_result"] = "blocked"
        run["outcome"] = dict.fromkeys(run["outcome"])
        report = self.evaluate()
        self.assertEqual(report["decision"], "block")
        metrics = report["candidate"]["overall"]
        self.assertEqual(metrics["unsafe_recommendations"], 1)
        self.assertEqual(metrics["unsafe_recommendations_blocked"], 1)
        self.assertAlmostEqual(metrics["false_remediation_rate"], 0.25)

    def test_segment_regression_cannot_hide_behind_global_accuracy(self):
        """A database improvement cannot compensate for a networking regression."""
        old = self.baseline["runs"][4]["decision"]
        old["status"] = "diagnosed"
        old["causal_change"] = "dns_config_change"
        new = self.candidate["runs"][4]["decision"]
        new["status"] = "diagnosed"
        new["hypotheses"][0]["cause"] = "connection_exhaustion"
        new["causal_change"] = "max_connections_500_to_300"
        report = self.evaluate()
        self.assertEqual(report["candidate"]["overall"]["diagnosis_accuracy"],
                         report["baseline"]["overall"]["diagnosis_accuracy"])
        self.assertTrue(any("networking: diagnosis_accuracy" in reason
                            for reason in report["reasons"]))
        self.assertEqual(report["decision"], "block")

    def test_critical_case_regression_is_reported_individually(self):
        """Quality cannot move from a critical case to an easier case in its segment."""
        self.dataset["cases"][0]["critical"] = True
        new = self.candidate["runs"][0]["decision"]
        new["hypotheses"][0]["cause"] = "slow_database_queries"
        report = self.evaluate()
        self.assertTrue(any("INC-2041: critical" in reason for reason in report["reasons"]))

    def test_missing_duplicate_or_extra_incidents_are_rejected(self):
        """Every version must answer exactly the same held-out cohort once."""
        for mutation in ("missing", "duplicate", "extra"):
            with self.subTest(mutation=mutation):
                version = deepcopy(self.candidate)
                if mutation == "missing":
                    version["runs"].pop()
                elif mutation == "duplicate":
                    version["runs"].append(deepcopy(version["runs"][0]))
                else:
                    version["runs"][0]["incident_id"] = "INC-unknown"
                with self.assertRaises(ValidationError):
                    evaluate_versions(self.dataset, version, self.baseline, self.policy)

    def test_speed_or_cost_cannot_override_quality_and_safety(self):
        """Each configured constraint is independently binding."""
        limits = {"maximum_mean_tool_calls": 2, "maximum_mean_diagnosis_ms": 100000,
                  "maximum_total_cost_usd": 0.1, "maximum_calibration_ece": 0.01}
        for key, value in limits.items():
            with self.subTest(key=key):
                policy = {**self.policy, key: value}
                self.assertEqual(evaluate_versions(
                    self.dataset, self.candidate, self.baseline, policy)["decision"], "block")

    def test_empty_denominators_are_null_and_abstention_cannot_game_gate(self):
        """An agent answering nothing cannot improve through empty denominators."""
        for run in self.candidate["runs"]:
            run["decision"].update(status="inconclusive", causal_change=None,
                                   selected_action=None, policy_result="not_requested")
            run["outcome"] = dict.fromkeys(run["outcome"])
        report = self.evaluate()
        metrics = report["candidate"]["overall"]
        self.assertEqual(report["decision"], "block")
        self.assertEqual(metrics["diagnosis_accuracy"], 0)
        self.assertIsNone(metrics["mean_diagnosis_ms"])
        self.assertIsNone(metrics["false_remediation_rate"])
        self.assertIsNone(metrics["calibration"]["ece"])

    def test_trace_schema_rejects_transcripts_and_raw_tool_payloads(self):
        """Only structured decisions, identifiers, timings, and statuses are accepted."""
        self.candidate["runs"][0]["decision"]["reasoning"] = "hidden transcript"
        with self.assertRaises(ValidationError):
            self.evaluate()
        self.candidate = fixture("candidate")
        self.candidate["runs"][0]["spans"][3]["raw_result"] = "unredacted log"
        with self.assertRaises(ValidationError):
            self.evaluate()

    def test_trace_tree_and_evidence_references_fail_closed(self):
        """Invalid parents, fabricated evidence, and failed evidence reads are rejected."""
        cases = []
        version = deepcopy(self.candidate)
        version["runs"][0]["spans"][1]["parent_id"] = "select"
        cases.append(version)
        version = deepcopy(self.candidate)
        version["runs"][0]["decision"]["evidence_ids"].append("missing-evidence")
        cases.append(version)
        version = deepcopy(self.candidate)
        version["runs"][0]["spans"][3]["status"] = "error"
        cases.append(version)
        version = deepcopy(self.candidate)
        version["runs"][0]["spans"][1]["duration_ms"] = 1000000
        cases.append(version)
        for version in cases:
            with self.subTest(version=version), self.assertRaises(ValidationError):
                evaluate_versions(self.dataset, version, self.baseline, self.policy)

    def test_evidence_must_be_collected_before_selection(self):
        """Future evidence cannot support an earlier decision."""
        self.candidate["runs"][0]["spans"][3]["start_ms"] = 200000
        with self.assertRaises(ValidationError):
            self.evaluate()

    def test_missing_evidence_recall_blocks_promotion(self):
        """Reducing tool use cannot hide a loss of required evidence."""
        self.candidate["runs"][0]["decision"]["evidence_ids"] = ["INC-2041-health"]
        report = self.evaluate()
        self.assertEqual(report["decision"], "block")
        self.assertTrue(any("evidence_recall" in reason for reason in report["reasons"]))

    def test_unknown_outcomes_are_not_implicit_successes(self):
        """Only verified and human-accepted actions can have operational outcomes."""
        run = self.candidate["runs"][0]
        run["outcome"]["human_accepted"] = None
        with self.assertRaises(ValidationError):
            self.evaluate()

    def test_policy_and_verification_cannot_precede_the_proposal(self):
        """A verification collected before policy review cannot validate this action."""
        spans = self.candidate["runs"][0]["spans"]
        next(span for span in spans if span["name"] == "verification")["start_ms"] = 0
        with self.assertRaises(ValidationError):
            self.evaluate()
        self.candidate = fixture("candidate")
        spans = self.candidate["runs"][0]["spans"]
        next(span for span in spans if span["name"] == "policy.evaluate")["start_ms"] = 125000
        with self.assertRaises(ValidationError):
            self.evaluate()

    def test_calibration_includes_confidence_one_in_the_last_bin(self):
        """Certain wrong answers produce Brier error rather than falling outside bins."""
        decision = self.candidate["runs"][0]["decision"]
        decision["hypotheses"] = [{"cause": "application_regression", "confidence": 1}]
        metrics = self.evaluate()["candidate"]["overall"]["calibration"]
        self.assertEqual(metrics["bins"][-1]["count"], 4)
        self.assertAlmostEqual(metrics["brier"], (1 + 3 * 0.06 ** 2) / 4)

    def test_unlisted_actions_count_as_false_remediation(self):
        """An action need not be explicitly forbidden to be an incorrect proposal."""
        self.candidate["runs"][0]["decision"]["selected_action"] = "increase_db_cpu"
        report = self.evaluate()
        self.assertEqual(report["candidate"]["overall"]["unsafe_recommendations"], 0)
        self.assertAlmostEqual(report["candidate"]["overall"]["false_remediation_rate"], 0.25)
        self.assertEqual(report["decision"], "block")

    def test_hashes_bind_inputs_without_exporting_alert_text(self):
        """A report identifies its inputs but does not copy the initial alert."""
        report = self.evaluate()
        digest = report["input_sha256"]["dataset"]
        self.dataset["cases"][0]["initial_alert"] = "changed alert"
        updated = self.evaluate()
        self.assertNotEqual(digest, updated["input_sha256"]["dataset"])
        self.assertNotIn("changed alert", json.dumps(updated))
        self.assertEqual(updated["traces"][0]["agent_version"], "sre-agent-v17")

    def test_numeric_and_hypothesis_edge_cases_are_rejected(self):
        """Nonfinite numbers and duplicated causes cannot distort metric denominators."""
        cases = []
        version = deepcopy(self.candidate)
        version["runs"][0]["usage"]["cost_usd"] = float("nan")
        cases.append(version)
        version = deepcopy(self.candidate)
        version["runs"][0]["spans"][0]["duration_ms"] = True
        cases.append(version)
        version = deepcopy(self.candidate)
        version["runs"][0]["decision"]["hypotheses"] *= 2
        cases.append(version)
        for version in cases:
            with self.subTest(version=version), self.assertRaises(ValidationError):
                evaluate_versions(self.dataset, version, self.baseline, self.policy)

    def test_cli_pass_and_invalid_input_exit_codes(self):
        """The published command is runnable and rejects invalid file shapes."""
        command = [sys.executable, "-m", "incident_copilot.evaluation_cli",
                   "--dataset", str(EXAMPLES / "incidents.json"),
                   "--candidate", str(EXAMPLES / "candidate.json"),
                   "--baseline", str(EXAMPLES / "baseline.json"),
                   "--policy", str(EXAMPLES / "promotion-policy.json")]
        passed = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(passed.returncode, 0, passed.stderr)
        self.assertEqual(json.loads(passed.stdout)["decision"], "pass")
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.json"
            policy_path.write_text(json.dumps({**self.policy, "minimum_accuracy": 1}),
                                   encoding="utf-8")
            command[-1] = str(policy_path)
            blocked = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(blocked.returncode, 1, blocked.stderr)
            self.assertEqual(json.loads(blocked.stdout)["decision"], "block")
        command[-1] = str(EXAMPLES / "incidents.json")
        invalid = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(invalid.returncode, 2)
        self.assertIn("Input rejected", invalid.stderr)


if __name__ == "__main__":
    unittest.main()
