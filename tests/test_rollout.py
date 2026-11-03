"""Exercise staged agent rollout, hard safety gates, and scoped HPA eligibility."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from incident_copilot.capability import approval_binding, review_capability
from incident_copilot.models import ValidationError
from incident_copilot.rollout import fingerprint, review_rollout


EXAMPLES = Path(__file__).parents[1] / "examples" / "rollout"


def fixture(name):
    """Read one synthetic Session 10 artifact."""
    return json.loads((EXAMPLES / f"{name}.json").read_text(encoding="utf-8"))


class RolloutTests(unittest.TestCase):
    """Check progression and stage permissions before broadening exposure."""

    def setUp(self):
        """Load the approved release and completed synthetic canary observations."""
        self.context = fixture("context")
        self.request = fixture("autonomy-request")
        self.replay = fixture("replay")

    def evaluate(self):
        """Review the mutable request against independent context and replay."""
        return review_rollout(self.context, self.request, self.replay)

    def test_every_adjacent_transition_has_a_specific_permission_ceiling(self):
        """The autonomy ladder limits capabilities even at the final production stage."""
        history = fixture("production-request")["history"]
        stages = ["offline", "shadow", "recommend", "prepare", "limited_autonomy", "production"]
        for index, level in enumerate((1, 2, 3, 4, 4)):
            with self.subTest(stage=stages[index + 1]):
                self.context["current_stage"] = stages[index]
                self.request.update(from_stage=stages[index], to_stage=stages[index + 1],
                                    history=history[:index], traffic_percent=5)
                result = self.evaluate()
                self.assertEqual(result["decision"], "eligible_for_next_stage", result["reasons"])
                self.assertEqual(result["permissions"]["maximum_level"], level)
                self.assertFalse(result["permissions"]["direct_production_mutation"])
                self.assertFalse(result["permissions"]["broader_remediation_level_5"])
                self.assertEqual(result["permissions"]["create_git_pr"], level >= 3)

    def test_skipped_fabricated_and_terminal_transitions_are_blocked(self):
        """A request cannot self-declare a later stage or bypass observed stages."""
        self.request["to_stage"] = "production"
        self.assertEqual(self.evaluate()["decision"], "block")
        self.request.update(from_stage="offline", to_stage="shadow", history=[])
        self.assertEqual(self.evaluate()["decision"], "block")
        self.context["current_stage"] = "production"
        self.request.update(from_stage="production", to_stage="production", history=[])
        self.assertEqual(self.evaluate()["decision"], "block")

    def test_all_prior_evidence_is_required_and_bound_to_the_release(self):
        """Last-stage success cannot replace missing history or another candidate's evidence."""
        for mutation in ("missing", "order", "release"):
            with self.subTest(mutation=mutation):
                self.request = fixture("autonomy-request")
                if mutation == "missing":
                    self.request["history"].pop(0)
                elif mutation == "order":
                    self.request["history"].reverse()
                else:
                    self.request["history"][0]["release"]["artifact_sha256"] = "0" * 64
                self.assertEqual(self.evaluate()["decision"], "block")

    def test_each_hard_violation_blocks_even_when_all_diagnoses_are_correct(self):
        """Safety cannot be offset by accuracy, acceptance, or speed."""
        for key in ("critical_unsafe_actions", "unauthorized_access", "policy_bypass",
                    "destructive_autonomous_actions"):
            with self.subTest(key=key):
                self.request = fixture("autonomy-request")
                self.request["history"][0][key] = 1
                result = self.evaluate()
                self.assertEqual(result["decision"], "block")
                self.assertIsNone(result["permissions"])

    def test_shadow_and_recommendation_have_no_write_or_visibility_shortcuts(self):
        """Shadow recommendations must stay invisible and cannot create PRs or mutate."""
        for key, value in (("engineer_visible", True), ("git_prs", 1),
                           ("production_mutations", 1)):
            with self.subTest(key=key):
                self.request = fixture("autonomy-request")
                self.request["history"][0][key] = value
                self.assertEqual(self.evaluate()["decision"], "block")
        self.request = fixture("autonomy-request")
        self.request["history"][1]["git_prs"] = 1
        self.assertEqual(self.evaluate()["decision"], "block")

    def test_scope_and_traffic_are_enforced_for_request_and_evidence(self):
        """Approval for payments does not authorize a new service or environment."""
        for key, value in (("services", ["admin-api"]), ("environment", "staging"),
                           ("traffic_percent", 6)):
            with self.subTest(key=key):
                self.request = fixture("autonomy-request")
                self.request[key] = value
                self.assertEqual(self.evaluate()["decision"], "block")
        self.request = fixture("autonomy-request")
        self.request["history"][0]["services"] = ["admin-api"]
        self.assertEqual(self.evaluate()["decision"], "block")

    def test_incident_volume_and_feedback_cannot_be_invented(self):
        """Unique incident counts and enough measured engineer feedback are required."""
        ids = self.request["history"][0]["incident_ids"]
        ids[1] = ids[0]
        with self.assertRaises(ValidationError):
            self.evaluate()
        self.request = fixture("autonomy-request")
        self.request["history"][0]["incident_ids"].pop()
        self.request["history"][0]["correct_diagnoses"] -= 1
        self.request["history"][0]["recommendation_count"] -= 1
        self.assertEqual(self.evaluate()["decision"], "block")
        self.request = fixture("autonomy-request")
        record = self.request["history"][1]
        for key in ("engineer_reviews", "engineer_accepted", "useful_recommendations"):
            record[key] = 1
        self.assertEqual(self.evaluate()["decision"], "block")

    def test_acceptance_alone_does_not_establish_usefulness(self):
        """Perfect engineer acceptance still fails when recommendations need correction."""
        self.request["history"][1]["engineer_corrections"] = 3
        self.assertEqual(self.evaluate()["decision"], "block")
        self.request = fixture("autonomy-request")
        self.request["history"][1]["useful_recommendations"] = 1
        self.assertEqual(self.evaluate()["decision"], "block")

    def test_live_quality_and_false_remediation_thresholds_are_hard_gates(self):
        """Offline success does not hide incorrect production recommendations."""
        self.request["history"][0]["correct_diagnoses"] = 40
        self.assertEqual(self.evaluate()["decision"], "block")
        self.request = fixture("autonomy-request")
        self.request["history"][1]["false_remediations"] = 1
        self.assertEqual(self.evaluate()["decision"], "block")

    def test_live_false_remediation_is_measured_per_recommendation(self):
        """Many incidents cannot dilute a single incorrect recommendation."""
        self.request["history"][0]["recommendation_count"] = 1
        self.request["history"][0]["false_remediations"] = 1
        self.assertEqual(self.evaluate()["decision"], "block")

    def test_explicit_no_action_proposal_cannot_pass_as_a_false_positive_response(self):
        """A classified no-change case must keep a null action and skip proposal tools."""
        replay = self.replay
        run = next(run for run in replay["candidate"]["runs"] if run["incident_id"] == "INC-2054")
        run["decision"].update(selected_action="no_action", policy_result="human_approval_required")
        spans = fixture("replay")["candidate"]["runs"][0]["spans"]
        run["spans"].extend(deepcopy(span) for span in spans
                            if span["name"] in {"remediation.propose", "policy.evaluate"})
        self.context["release"]["candidate_sha256"] = fingerprint(replay["candidate"])
        self.context["replay_sha256"] = fingerprint(replay)
        result = self.evaluate()
        self.assertEqual(result["decision"], "block")
        self.assertEqual(result["offline_decision"], "pass")
        self.assertTrue(any("expected no change or escalation" in reason
                            for reason in result["reasons"]))

    def test_offline_replay_is_recomputed_and_bound_to_the_candidate(self):
        """A changed prompt or weakened replay cannot inherit a prior release's pass."""
        self.replay["candidate"]["configuration"]["prompt"] = "unreviewed-prompt"
        self.assertEqual(self.evaluate()["decision"], "block")
        self.replay = fixture("replay")
        self.replay["policy"]["minimum_accuracy"] = 1
        self.assertEqual(self.evaluate()["decision"], "block")

    def test_offline_safety_audits_require_zero_violations_and_complete_coverage(self):
        """Forbidden access and policy bypass are hard gates even without a proposed action."""
        for key in ("unauthorized_access", "policy_bypass", "destructive_autonomous_actions",
                    "critical_unsafe_actions"):
            with self.subTest(key=key):
                self.replay = fixture("replay")
                self.replay["safety_audits"][0][key] = 1
                self.context["replay_sha256"] = fingerprint(self.replay)
                result = self.evaluate()
                self.assertEqual(result["decision"], "block")
                self.assertTrue(any("offline hard safety" in reason
                                    for reason in result["reasons"]))
        self.replay = fixture("replay")
        self.replay["safety_audits"].pop()
        self.context["replay_sha256"] = fingerprint(self.replay)
        self.assertEqual(self.evaluate()["decision"], "block")

    def test_failed_verification_or_rollback_blocks_further_promotion(self):
        """Prior operational failures cannot disappear behind a successful latest stage."""
        for key in ("verification_failures", "rollback_failures"):
            with self.subTest(key=key):
                self.request = fixture("autonomy-request")
                self.request["history"][2][key] = 1
                self.assertEqual(self.evaluate()["decision"], "block")

    def test_no_action_and_escalation_scenarios_cannot_reward_a_proposal(self):
        """An abstention or false alarm must not turn into a production recommendation."""
        cases = self.replay["dataset"]["cases"]
        for scenario in ("false_positive", "insufficient_evidence"):
            with self.subTest(scenario=scenario):
                self.replay = fixture("replay")
                incident = next(case for case in cases if case["scenario"] == scenario)
                run = next(run for run in self.replay["candidate"]["runs"]
                           if run["incident_id"] == incident["incident_id"])
                run["decision"]["status"] = "diagnosed" if scenario == "insufficient_evidence" \
                    else "inconclusive"
                run["decision"]["causal_change"] = None
                self.context["release"]["candidate_sha256"] = fingerprint(self.replay["candidate"])
                self.request["release"] = deepcopy(self.context["release"])
                for record in self.request["history"]:
                    record["release"] = deepcopy(self.context["release"])
                result = self.evaluate()
                self.assertEqual(result["decision"], "block")
                self.assertTrue(any("expected no change or escalation" in reason
                                    for reason in result["reasons"]))

    def test_autonomy_requires_preparation_and_verified_actions_before_production(self):
        """A successful label cannot replace a reviewed PR, rollback drill, or verification."""
        self.request["history"][2]["rollback_drills"] = 0
        self.assertEqual(self.evaluate()["decision"], "block")
        self.context = fixture("production-context")
        self.request = fixture("production-request")
        self.request["history"][-1]["verified_mutations"] = 4
        self.assertEqual(self.evaluate()["decision"], "block")
        self.request = fixture("production-request")
        self.request["history"][-1]["capability_ids"] = ["all-hpas"]
        self.assertEqual(self.evaluate()["decision"], "block")


class CapabilityTests(unittest.TestCase):
    """Preserve Stage 3 checks and an exact external preapproval for bounded automation."""

    def setUp(self):
        """Load the synthetic payments capacity pattern and exact HPA plan."""
        self.platform = fixture("capability-platform")
        self.intent = fixture("hpa-intent")
        self.plan = fixture("hpa-plan")
        self.replay = fixture("replay")

    def evaluate(self):
        """Review the capability without contacting a controller."""
        return review_capability(self.platform, self.intent, self.plan, self.replay)

    def test_17_successes_and_exact_preapproval_produce_scoped_eligibility(self):
        """A healthy pattern and immutable approval binding produce a review artifact."""
        result = self.evaluate()
        self.assertEqual(result["decision"], "eligible_for_preapproved_gitops", result["reasons"])
        self.assertEqual(result["proposed_change"]["before"], 10)
        self.assertEqual(result["proposed_change"]["after"], 20)
        self.assertEqual(result["stage3_decision"], "requires_human_approval")

    def test_missing_expired_changed_or_lower_tier_preapproval_requires_review(self):
        """The agent cannot grant itself approval or change the reviewed verification."""
        for mutation in ("missing", "expired", "digest", "tier"):
            with self.subTest(mutation=mutation):
                self.platform = fixture("capability-platform")
                approval = self.platform["preapproval"]
                if mutation == "missing":
                    self.platform["preapproval"] = None
                elif mutation == "expired":
                    approval["expires_at"] = self.platform["evaluated_at"]
                elif mutation == "digest":
                    approval["binding_sha256"] = "0" * 64
                else:
                    approval["approved_by_tier"] = "operator"
                self.assertEqual(self.evaluate()["decision"], "requires_human_review")

    def test_capacity_threshold_boundaries_and_confidence_fail_closed(self):
        """Equality at a strict capacity threshold is insufficient for autonomy."""
        for key, value in (("cpu_percent", 90), ("traffic_ratio", 1.5),
                           ("db_cpu_fraction", 0.7), ("db_connections_fraction", 0.7),
                           ("available_capacity_fraction", 0.3), ("error_budget_remaining", 0.5)):
            with self.subTest(key=key):
                self.platform = fixture("capability-platform")
                self.platform["observations"][key] = value
                self.assertEqual(self.evaluate()["decision"], "requires_human_review")
        self.platform = fixture("capability-platform")
        self.intent["confidence"] = 0.90
        self.assertEqual(self.evaluate()["decision"], "requires_human_review")

    def test_history_staleness_failed_examples_and_future_metrics_require_review(self):
        """Historical failures and stale measurements defeat the successful-pattern claim."""
        self.platform["observations"]["historical_attempts"] = 18
        self.assertEqual(self.evaluate()["decision"], "requires_human_review")
        for when in ("2026-11-02T11:54:59Z", "2026-11-02T12:00:01Z"):
            with self.subTest(when=when):
                self.platform = fixture("capability-platform")
                self.platform["observations"]["observed_at"] = when
                self.assertEqual(self.evaluate()["decision"], "requires_human_review")

    def test_target_change_and_extra_plan_changes_never_gain_autonomy(self):
        """An exact HPA grant cannot authorize another service or an extra resource."""
        self.intent["resource"] = "checkout-api"
        self.assertEqual(self.evaluate()["decision"], "requires_human_review")
        self.intent = fixture("hpa-intent")
        self.plan["changes"].append(deepcopy(self.plan["changes"][0]))
        self.assertEqual(self.evaluate()["decision"], "requires_human_review")

    def test_weakened_verification_or_oversized_changes_require_new_review(self):
        """Preapproval binds SLO thresholds and the complete normalized plan."""
        self.intent["verification"]["success_criteria"]["http_error_rate"]["value"] = 0.5
        self.assertEqual(self.evaluate()["decision"], "requires_human_review")
        self.intent = fixture("hpa-intent")
        self.intent["desired_state"]["hpa.maxReplicas"] = 21
        self.plan["changes"][0]["after"] = 21
        self.assertEqual(self.evaluate()["decision"], "requires_human_review")

    def test_signed_binding_cannot_remove_required_saturation_checks(self):
        """Mandatory verification metrics apply even to an internally consistent approval."""
        self.intent["verification"]["failure_criteria"].pop("db_connections")
        self.platform["preapproval"]["binding_sha256"] = approval_binding(
            self.platform["rollout_context"]["release"], self.platform["capability"],
            self.intent, self.plan)
        self.assertEqual(self.evaluate()["decision"], "requires_human_review")

    def test_malformed_authority_and_unknown_fields_are_rejected(self):
        """A model cannot add an approval flag or use booleans as numeric evidence."""
        self.intent["approved"] = True
        with self.assertRaises(ValidationError):
            self.evaluate()
        self.intent = fixture("hpa-intent")
        self.platform["observations"]["cpu_percent"] = True
        with self.assertRaises(ValidationError):
            self.evaluate()

    def test_cli_exit_codes_cover_eligible_blocked_and_invalid_artifacts(self):
        """The published command provides CI-usable decisions and invalid-input errors."""
        command = [sys.executable, "-m", "incident_copilot.rollout_cli", "promotion",
                   "--context", str(EXAMPLES / "context.json"),
                   "--request", str(EXAMPLES / "autonomy-request.json"),
                   "--replay", str(EXAMPLES / "replay.json")]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        with tempfile.TemporaryDirectory() as directory:
            request = fixture("autonomy-request")
            request["history"][0]["policy_bypass"] = 1
            path = Path(directory) / "blocked.json"
            path.write_text(json.dumps(request), encoding="utf-8")
            command[command.index("--request") + 1] = str(path)
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1, result.stderr)
            path.write_text("{}", encoding="utf-8")
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
