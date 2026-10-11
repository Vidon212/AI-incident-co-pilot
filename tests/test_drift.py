"""Classify drift with trusted provenance and fail closed on unsafe advice."""

from copy import deepcopy
import json
from pathlib import Path
import unittest

from incident_copilot.drift import evaluate_drift
from incident_copilot.models import ValidationError


ROOT = Path(__file__).parents[1]


def fixture(name):
    with (ROOT / "examples" / "drift" / name).open(encoding="utf-8") as source:
        return json.load(source)


class DriftPolicyTests(unittest.TestCase):
    def evaluate(self, case):
        return evaluate_drift(fixture(f"{case}-record.json"),
                              fixture(f"{case}-assessment.json"))

    def test_controller_state_is_ignored(self):
        result = self.evaluate("a-hpa")
        self.assertEqual(result.classification, "CONTROLLER_STATE")
        self.assertEqual(result.decision, "no_action")
        self.assertFalse(result.requires_human_approval)

    def test_suspicious_manual_change_requires_investigation(self):
        result = self.evaluate("b-manual")
        self.assertEqual(result.classification, "ACCIDENTAL_DRIFT")
        self.assertEqual(result.decision, "investigate")

    def test_emergency_change_is_backported_before_reconciliation(self):
        result = self.evaluate("c-emergency")
        self.assertEqual(result.classification, "EMERGENCY_DRIFT")
        self.assertEqual(result.recommended_action, "BACKPORT_TO_GIT")
        self.assertEqual(result.approval, "incident_commander")

    def test_provider_expansion_updates_desired_state(self):
        result = self.evaluate("d-provider")
        self.assertEqual(result.classification, "EXPECTED_DRIFT")
        self.assertEqual(result.recommended_action, "UPDATE_DESIRED_STATE")
        self.assertIn("Do not reverse", " ".join(result.reasons))

    def test_model_cannot_turn_emergency_drift_into_reconciliation(self):
        record = fixture("c-emergency-record.json")
        assessment = fixture("c-emergency-assessment.json")
        assessment.update(classification="ACCIDENTAL_DRIFT",
                          recommended_action="RECONCILE_VIA_GITOPS",
                          risk_of_reconciliation="LOW")
        result = evaluate_drift(record, assessment)
        self.assertEqual(result.decision, "investigate")
        self.assertEqual(result.classification, "UNKNOWN")
        self.assertFalse(result.requires_human_approval)

    def test_low_confidence_fails_closed(self):
        assessment = fixture("a-hpa-assessment.json")
        assessment["confidence"] = 0.79
        self.assertEqual(evaluate_drift(fixture("a-hpa-record.json"), assessment).decision,
                         "investigate")

    def test_no_difference_needs_no_action(self):
        record = fixture("b-manual-record.json")
        record["observed"] = record["desired"]
        result = evaluate_drift(record, fixture("b-manual-assessment.json"))
        self.assertFalse(result.drift_detected)
        self.assertEqual(result.classification, "NO_DRIFT")

    def test_regressing_signals_do_not_validate_emergency_drift(self):
        record = fixture("c-emergency-record.json")
        record["reliability"]["after"]["http_error_rate"] = 0.20
        result = evaluate_drift(record, fixture("c-emergency-assessment.json"))
        self.assertEqual(result.decision, "investigate")

    def test_incomplete_emergency_provenance_fails_closed(self):
        """Incident timing alone cannot establish emergency drift provenance."""
        assessment = fixture("c-emergency-assessment.json")
        for key, value in (("actor", None), ("changed_at", None),
                           ("auto_reconcile_enabled", True)):
            with self.subTest(key=key):
                record = fixture("c-emergency-record.json")
                record["provenance"][key] = value
                self.assertEqual(evaluate_drift(record, assessment).decision, "investigate")

    def test_malformed_inputs_are_rejected(self):
        record = fixture("c-emergency-record.json")
        assessment = fixture("c-emergency-assessment.json")
        bad_inputs = []
        changed = deepcopy(record)
        changed["approved"] = True
        bad_inputs.append((changed, assessment))
        changed = deepcopy(record)
        changed["desired"] = {"memory": 1024}
        bad_inputs.append((changed, assessment))
        changed = deepcopy(record)
        changed["reliability"]["before"]["oomkills"] = float("nan")
        bad_inputs.append((changed, assessment))
        changed_assessment = deepcopy(assessment)
        changed_assessment["recommended_action"] = "APPLY_NOW"
        bad_inputs.append((record, changed_assessment))
        for raw_record, raw_assessment in bad_inputs:
            with self.subTest(record=raw_record, assessment=raw_assessment):
                with self.assertRaises(ValidationError):
                    evaluate_drift(raw_record, raw_assessment)


if __name__ == "__main__":
    unittest.main()
