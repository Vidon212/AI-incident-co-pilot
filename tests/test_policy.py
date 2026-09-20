"""Tests for the deterministic remediation-authority policy."""

import unittest

from incident_copilot.models import Diagnosis, IncidentContext, ValidationError
from incident_copilot.policy import evaluate


def context() -> IncidentContext:
    """Build a representative incident context for policy tests."""
    return IncidentContext.from_dict({
        "service": "checkout-api", "namespace": "production", "deployment": "checkout-api",
        "http_503_rate": 14.0, "pod_restarts": 0, "cpu_percent": 31.0, "memory_percent": 47.0,
        "recent_events": ["Readiness probe failed: 503"], "current_image_tag": "v2.19.0",
        "previous_image_tag": "v2.18.4", "deployment_minutes_before_alert": 7,
    })


def diagnosis(**overrides: object) -> Diagnosis:
    """Build a valid diagnosis with selected test-specific overrides."""
    data: dict[str, object] = {
        "service": "checkout-api", "severity": "high", "suspected_cause": "application regression",
        "confidence": 0.82, "evidence": ["503 after deploy"], "recommended_action": "rollback",
        "requires_human_approval": True,
    }
    data.update(overrides)
    return Diagnosis.from_dict(data)


class PolicyTests(unittest.TestCase):
    """Verify policy routes untrusted diagnosis data safely."""

    def test_rollback_requires_human_approval_and_proposes_git_change(self) -> None:
        """A high-confidence rollback still requires human approval."""
        result = evaluate(context(), diagnosis())
        self.assertEqual(result.decision, "requires_human_approval")
        self.assertEqual(result.proposed_git_change["image.tag"], "v2.18.4")

    def test_low_confidence_routes_to_investigation(self) -> None:
        """Low-confidence diagnosis cannot propose a change."""
        result = evaluate(context(), diagnosis(confidence=0.79))
        self.assertEqual(result.decision, "investigate")
        self.assertIsNone(result.proposed_git_change)

    def test_service_mismatch_cannot_propose_change(self) -> None:
        """Diagnosis for another service cannot affect this incident."""
        result = evaluate(context(), diagnosis(service="payments-api"))
        self.assertEqual(result.decision, "no_change")

    def test_unknown_action_is_rejected(self) -> None:
        """Reject actions outside the permitted policy contract."""
        with self.assertRaises(ValidationError):
            diagnosis(recommended_action="kubectl rollout undo")


if __name__ == "__main__":
    unittest.main()
