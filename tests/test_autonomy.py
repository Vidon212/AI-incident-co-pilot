"""Prove that confidence, urgency, and untrusted intent cannot bypass autonomy gates."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import unittest

from incident_copilot.autonomy import review_autonomy
from incident_copilot.autonomy_contracts import manual_approval_binding
from incident_copilot.models import ValidationError
from incident_copilot.rollout import fingerprint


ROOT = Path(__file__).resolve().parents[1]


def fixture(name, directory="autonomy"):
    """Load a fresh synthetic evidence snapshot."""
    return json.loads((ROOT / "examples" / directory / f"{name}.json").read_text(encoding="utf-8"))


class AutonomyHarness(unittest.TestCase):
    """Provide independent copies and explicit fixture rebinding."""

    def setUp(self):
        """Start with the already scoped, preapproved HPA profile."""
        self.proposal = fixture("hpa-proposal")
        self.context = fixture("hpa-context")
        self.platform = fixture("capability-platform", "rollout")
        self.replay = fixture("replay", "rollout")

    def review(self, auto=False, bundle=None):
        """Rebind deliberate proposal edits as a trusted test collector would."""
        self.context["proposal_sha256"] = fingerprint(self.proposal)
        return review_autonomy(self.proposal, self.context, self.platform if auto else None,
                               self.replay if auto else None, bundle)

    def rollback(self):
        """Load a rollback with exact Stage 3 plan and independent manual approval."""
        self.proposal = fixture("rollback-proposal")
        self.context = fixture("rollback-context")


class AutonomyLadderTests(AutonomyHarness):
    """Check the six levels, fixed vetoes, and separation of urgency from authority."""

    def test_all_six_levels_have_distinct_evidence_requirements(self):
        """Only the scoped HPA catalog can reach preapproved execution eligibility."""
        self.context["enabled"] = False
        self.assertEqual(self.review()["autonomy_level"], 0)
        self.context["enabled"] = True
        self.proposal["confidence"] = .79
        self.assertEqual(self.review()["autonomy_level"], 1)
        self.proposal["confidence"] = .85
        self.assertEqual(self.review()["autonomy_level"], 2)
        self.proposal["confidence"] = .94
        self.assertEqual(self.review()["autonomy_level"], 3)
        self.assertEqual(self.review(auto=True)["autonomy_level"], 5)
        self.rollback()
        self.assertEqual(self.review()["autonomy_level"], 4)

    def test_level5_transaction_binds_success_timeout_and_failure_behavior(self):
        """Verification and recovery criteria exist before an executor could act."""
        result = self.review(auto=True)
        self.assertEqual(result["capability_level"], "EXECUTE_AND_VERIFY")
        transaction = result["transaction"]
        self.assertEqual(transaction["verification"], self.proposal["verification"])
        self.assertEqual(transaction["timeout_minutes"], 10)
        self.assertEqual(transaction["unexpected_signal"], "freeze_and_escalate")
        self.assertIn("reviewed_git_revert", transaction["degradation"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["merge_authorized"])

    def test_confidence_cannot_authorize_database_recreation(self):
        """Even 99.7% confidence and urgent SLO burn leave a destructive action advisory."""
        self.proposal = fixture("recreate-proposal")
        self.context = fixture("recreate-context")
        result = self.review()
        self.assertEqual(result["autonomy_level"], 2)
        self.assertEqual(result["urgency"], "high")
        self.assertEqual(result["escalation"], "immediate_human")
        self.assertIsNone(result["transaction"])

    def test_schema_migration_removes_rollback_execution_eligibility(self):
        """One incompatible migration overrides a known-good image and a successful history."""
        self.rollback()
        self.context = fixture("migration-context")
        result = self.review()
        self.assertEqual(result["autonomy_level"], 2)
        self.assertEqual(result["escalation"], "immediate_human")

    def test_error_budget_pressure_never_raises_permissions(self):
        """Low remaining budget increases approval tier and urgency, not capability level."""
        self.rollback()
        self.context["error_budget_remaining"] = .04
        self.context["remediation_context"]["error_budget_remaining"] = .04
        self.context["burn_rate"] = 14
        result = self.review()
        self.assertEqual(result["autonomy_level"], 3)
        self.assertEqual(result["stage3_review"]["approval"], "incident_commander")
        self.assertEqual(result["escalation"], "immediate_human")

    def test_headroom_history_blast_radius_and_transition_are_independent_caps(self):
        """High confidence cannot compensate for any failed action-risk dimension."""
        for key, value in (("cluster_headroom", .29), ("downstream_headroom", .29),
                           ("historical_attempts", 0), ("change_risk", "high"),
                           ("transition", "restart"), ("reversibility", "unknown")):
            with self.subTest(key=key):
                self.context = fixture("hpa-context")
                self.context[key] = value
                if key == "historical_attempts":
                    self.context["historical_successes"] = 0
                self.assertLessEqual(self.review()["autonomy_level"], 3)

    def test_stale_future_or_unknown_risk_requires_investigation(self):
        """No local evidence can be declared fresh merely because the incident is severe."""
        for key, value in (("observed_at", "2026-11-01T12:00:00Z"),
                           ("observed_at", "2026-11-03T12:00:00Z"),
                           ("change_risk", "unknown"), ("transition", "unknown")):
            with self.subTest(key=key):
                self.context = fixture("hpa-context")
                self.context[key] = value
                self.assertEqual(self.review()["autonomy_level"], 1)

    def test_action_allowlist_and_missing_control_path_cannot_be_bypassed(self):
        """An otherwise valid diagnosis does not grant scope outside platform policy."""
        self.context["allowed_actions"] = []
        self.assertEqual(self.review(auto=True)["autonomy_level"], 0)
        self.context["allowed_actions"] = ["increase_hpa_max"]
        self.context["gitops_managed"] = False
        self.assertEqual(self.review(auto=True)["autonomy_level"], 2)


class AutonomyBindingTests(AutonomyHarness):
    """Preserve plan, identity, approval, simulation, and rollout bindings."""

    def test_expired_weak_or_reused_manual_approval_stays_prepare_only(self):
        """A human receipt must bind the exact state and meet the Stage 3 tier."""
        for key, value in (("expires_at", "2026-11-02T11:00:00Z"),
                           ("approved_by_tier", "operator"), ("binding_sha256", "0" * 64)):
            with self.subTest(key=key):
                self.rollback()
                self.context["approval"][key] = value
                self.assertEqual(self.review()["autonomy_level"], 3)
        self.rollback()
        self.context["cluster_headroom"] = .5
        self.assertEqual(self.review()["autonomy_level"], 3)

    def test_independent_commander_can_approve_low_budget_but_not_bypass_safety(self):
        """A stronger receipt supports Level 4 after all other Stage 3 checks still pass."""
        self.rollback()
        self.context["error_budget_remaining"] = .04
        self.context["remediation_context"]["error_budget_remaining"] = .04
        approval = self.context["approval"]
        approval["approved_by_tier"] = "incident_commander"
        approval["binding_sha256"] = manual_approval_binding(self.proposal, self.context)
        self.assertEqual(self.review()["autonomy_level"], 4)
        self.context["backward_incompatible_migration"] = True
        self.assertEqual(self.review()["autonomy_level"], 2)

    def test_plan_tampering_or_missing_verification_cannot_get_execution_level(self):
        """Full-plan comparison and predeclared verification survive autonomy review."""
        self.context["plan"]["changes"][0]["after"] = 21
        self.assertEqual(self.review()["autonomy_level"], 2)
        self.context = fixture("hpa-context")
        self.proposal["verification"] = None
        self.assertEqual(self.review()["autonomy_level"], 2)
        self.proposal = fixture("hpa-proposal")
        self.context["plan"] = None
        self.assertEqual(self.review()["autonomy_level"], 3)

    def test_preapproval_expiry_and_rollout_failure_downgrade_level5(self):
        """The new engine cannot self-certify the existing rollout or preapproval gates."""
        self.platform["preapproval"]["expires_at"] = "2026-11-02T11:00:00Z"
        self.assertEqual(self.review(auto=True)["autonomy_level"], 3)
        self.platform = fixture("capability-platform", "rollout")
        self.platform["rollout_request"]["history"][0]["critical_unsafe_actions"] = 1
        self.assertEqual(self.review(auto=True)["autonomy_level"], 3)

    def test_verification_contract_changes_invalidate_existing_preapproval(self):
        """Reusing a grant after changing a measurable threshold cannot reach Level 5."""
        self.proposal["verification"]["success_criteria"]["p95_latency_ms"]["value"] = 650
        self.assertEqual(self.review(auto=True)["autonomy_level"], 3)

    def test_contradictory_risk_capability_or_scope_is_rejected(self):
        """Risk labels cannot silently replace the facts used by the scoped capability."""
        self.context["cluster_headroom"] = .9
        with self.assertRaises(ValidationError):
            self.review(auto=True)
        self.context = fixture("hpa-context")
        self.context["resource"] = "unrelated-api"
        with self.assertRaises(ValidationError):
            self.review()
        self.context = fixture("hpa-context")
        self.context["affected_services"].append("another-api")
        with self.assertRaises(ValidationError):
            self.review()

    def test_recomputed_simulation_caps_database_change_at_preparation(self):
        """A restart and multiple affected services keep a 96% confidence proposal at Level 3."""
        self.proposal = fixture("database-proposal")
        self.context = fixture("database-context")
        bundle = fixture("database-impact-bundle")
        result = self.review(bundle=bundle)
        self.assertEqual(result["autonomy_level"], 3)
        self.assertEqual(result["impact_review"]["score"]["value"], 70)
        self.context["change_risk"] = "low"
        self.assertEqual(self.review(bundle=bundle)["autonomy_level"], 3)
        self.assertEqual(self.review()["autonomy_level"], 1)
        bundle["change"]["after"]["max_connections"] = 601
        with self.assertRaises(ValidationError):
            self.review(bundle=bundle)

    def test_model_cannot_supply_execution_authority_or_nonfinite_confidence(self):
        """Unknown authority fields and invalid numerical certainty fail input validation."""
        for value in (True, float("nan"), float("inf"), 1.1):
            with self.subTest(value=value):
                self.proposal["confidence"] = value
                with self.assertRaises(ValidationError):
                    self.review()
        self.proposal = fixture("hpa-proposal")
        self.proposal["execution_authorized"] = True
        with self.assertRaises(ValidationError):
            self.review()

    def test_review_is_repeatable_read_only_and_fingerprinted(self):
        """The decision binds the full input set and cannot mutate its evidence sources."""
        before = deepcopy((self.proposal, self.context, self.platform, self.replay))
        result = self.review(auto=True)
        self.assertEqual(result, self.review(auto=True))
        self.assertEqual(before, (self.proposal, self.context, self.platform, self.replay))
        digest = result.pop("review_sha256")
        self.assertEqual(digest, fingerprint(result))

    def test_published_cli_example_returns_eligibility_without_execution(self):
        """The real CLI composes the existing capability and replay artifacts."""
        result = subprocess.run([sys.executable, "-m", "incident_copilot.autonomy_cli",
                                 "--proposal", "examples/autonomy/hpa-proposal.json", "--context",
                                 "examples/autonomy/hpa-context.json", "--capability-platform",
                                 "examples/rollout/capability-platform.json", "--replay",
                                 "examples/rollout/replay.json"], cwd=ROOT,
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["autonomy_level"], 5)
        self.assertFalse(report["execution_authorized"])
