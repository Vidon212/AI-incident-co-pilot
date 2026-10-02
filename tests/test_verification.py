"""Verify SLO outcomes and reject misleading recovery signals."""

from copy import deepcopy
import json
from pathlib import Path
import unittest

from incident_copilot.models import ValidationError
from incident_copilot.remediation import RemediationIntent, verification_digest
from incident_copilot.verification import evaluate_verification


ROOT = Path(__file__).resolve().parents[1] / "examples"


def fixture(path):
    """Load a published verification example."""
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


class VerificationTests(unittest.TestCase):
    """Test mitigation, root-cause, and control-signal decisions."""

    def setUp(self):
        self.intent = fixture("verification/checkout_rollback_intent.json")
        self.observations = fixture("verification/checkout_rollback_observations.json")

    def evaluate(self):
        """Evaluate a per-test copy of the rollback incident."""
        return evaluate_verification(self.intent, self.observations)

    def test_checkout_sli_improvement_succeeds(self):
        """User SLIs, not deployment status, establish mitigation success."""
        result = self.evaluate()
        self.assertEqual(result.outcome, "SUCCESS")
        self.assertEqual(result.underlying_problem, "not_assessed")

    def test_healthy_deployment_does_not_override_failed_sli(self):
        """Healthy pods do not override a failed user-facing SLI."""
        self.observations["after"]["metrics"]["http_error_rate"] = 0.06
        result = self.evaluate()
        self.assertEqual(result.outcome, "FAILED")
        self.assertIn("Failure threshold triggered: http_error_rate.", result.reasons)

    def test_critical_alert_fails_even_when_slis_pass(self):
        """A new critical alert is an explicit failure condition."""
        self.observations["new_critical_alert"] = True
        self.assertEqual(self.evaluate().outcome, "FAILED")

    def test_traffic_drop_makes_recovery_inconclusive(self):
        """A traffic decline can explain apparent recovery."""
        self.observations["after"]["metrics"]["throughput_rps"] = 100
        self.assertEqual(self.evaluate().outcome, "INCONCLUSIVE")

    def test_dependency_recovery_makes_attribution_inconclusive(self):
        """Independent dependency recovery confounds attribution."""
        self.observations["after"]["metrics"]["db_p95_latency_ms"] = 60
        self.assertEqual(self.evaluate().outcome, "INCONCLUSIVE")

    def test_contract_or_change_mismatch_cannot_succeed(self):
        """A changed contract or execution target cannot pass verification."""
        self.observations["execution"]["approved_contract_sha256"] = "0" * 64
        self.assertEqual(self.evaluate().outcome, "INCONCLUSIVE")
        self.observations = fixture("verification/checkout_rollback_observations.json")
        self.observations["execution"]["after"] = "v2.18"
        self.assertEqual(self.evaluate().outcome, "INCONCLUSIVE")

    def test_missing_metrics_cannot_succeed(self):
        """Incomplete collector snapshots fail closed."""
        del self.observations["after"]["metrics"]["http_error_rate"]
        self.assertEqual(self.evaluate().outcome, "INCONCLUSIVE")

    def test_short_or_misordered_windows_are_rejected(self):
        """The contracted window must occur after execution."""
        self.observations["after"]["end"] = "2026-09-28T12:15:00Z"
        with self.assertRaises(ValidationError):
            self.evaluate()
        self.observations = fixture("verification/checkout_rollback_observations.json")
        self.observations["after"]["start"] = "2026-09-28T12:09:00Z"
        with self.assertRaises(ValidationError):
            self.evaluate()

    def test_preexisting_success_is_inconclusive(self):
        """Already healthy SLIs provide no evidence of improvement."""
        self.observations["before"]["metrics"].update(
            checkout_completion_rate=0.995, http_error_rate=0.005, p95_latency_ms=500,
        )
        self.assertEqual(self.evaluate().outcome, "INCONCLUSIVE")

    def test_memory_mitigation_does_not_resolve_root_cause(self):
        """Memory growth above history remains an unresolved concern."""
        intent = fixture("verification/checkout_memory_intent.json")
        observations = fixture("verification/checkout_memory_observations.json")
        result = evaluate_verification(intent, observations)
        self.assertEqual(result.outcome, "SUCCESS")
        self.assertEqual(result.underlying_problem, "unresolved")

    def test_infrastructure_recovery_alone_cannot_claim_user_recovery(self):
        """Passing SLIs before execution cannot gain credit from CPU recovery."""
        self.intent["verification"]["success_criteria"]["pod_cpu_percent"] = {
            "op": "lt", "value": 60,
        }
        self.observations["execution"]["approved_contract_sha256"] = verification_digest(
            self.intent["verification"])
        self.observations["before"]["metrics"].update(
            checkout_completion_rate=0.995, http_error_rate=0.005,
            p95_latency_ms=500, pod_cpu_percent=82,
        )
        self.observations["after"]["metrics"]["pod_cpu_percent"] = 48
        self.assertEqual(self.evaluate().outcome, "INCONCLUSIVE")

    def test_known_failure_takes_precedence_over_baseline_gap(self):
        """Missing historical memory cannot hide alerts or missed service targets."""
        intent = fixture("verification/checkout_memory_intent.json")
        for alert, error_rate in ((True, 0.012), (False, 0.03), (False, 0.06)):
            with self.subTest(alert=alert, error_rate=error_rate):
                observations = fixture("verification/checkout_memory_observations.json")
                observations["historical_baseline"] = {}
                observations["new_critical_alert"] = alert
                observations["after"]["metrics"]["http_error_rate"] = error_rate
                result = evaluate_verification(intent, observations)
                self.assertEqual(result.outcome, "FAILED")

    def test_failed_sli_takes_precedence_over_traffic_confounding(self):
        """Attribution uncertainty cannot hide an unmet success threshold."""
        self.observations["after"]["metrics"].update(
            http_error_rate=0.03, throughput_rps=100,
        )
        self.assertEqual(self.evaluate().outcome, "FAILED")

    def test_payments_control_signals_are_recorded(self):
        """Scaling requires the five service and capacity signals."""
        intent = fixture("remediation/payments_scale_intent.json")
        observations = fixture("verification/payments_scale_observations.json")
        result = evaluate_verification(intent, observations)
        self.assertEqual(result.outcome, "SUCCESS")
        self.assertEqual(result.evaluated_signals["after"]["pod_cpu_percent"], 50)
        self.assertEqual(result.evaluated_signals["after"]["db_connections"], 130)
        del observations["after"]["metrics"]["pod_cpu_percent"]
        self.assertEqual(evaluate_verification(intent, observations).outcome, "INCONCLUSIVE")

    def test_payments_db_saturation_fails_despite_latency_recovery(self):
        """Downstream capacity is an explicit failure guardrail."""
        intent = fixture("remediation/payments_scale_intent.json")
        observations = fixture("verification/payments_scale_observations.json")
        observations["after"]["metrics"]["db_connections"] = 190
        self.assertEqual(evaluate_verification(intent, observations).outcome, "FAILED")

    def test_untrusted_contract_cannot_omit_user_sli_or_weaken_alert(self):
        """Model-proposed criteria cannot skip mandatory safety conditions."""
        for change in (
            {"success_criteria": {"pod_cpu_percent": {"op": "lt", "value": 50}}},
            {"new_critical_alert_fails": False},
            {"observation_window_minutes": True},
            {"failure_criteria": {"http_error_rate": {"op": [], "value": 0.05}}},
        ):
            with self.subTest(change=change):
                intent = deepcopy(self.intent)
                intent["verification"].update(change)
                with self.assertRaises(ValidationError):
                    RemediationIntent.from_dict(intent)


if __name__ == "__main__":
    unittest.main()
