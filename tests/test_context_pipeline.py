"""Tests for deterministic incident-context normalization and ranking."""

import json
import unittest
from pathlib import Path

from incident_copilot.context_pipeline import build_incident_context
from incident_copilot.models import ValidationError


EXAMPLE = Path("examples/checkout_incident_evidence.json")


class ContextPipelineTests(unittest.TestCase):
    """Verify context construction rejects malformed collector output."""

    def source(self) -> dict:
        """Load representative checkout incident evidence."""
        return json.loads(EXAMPLE.read_text(encoding="utf-8"))

    def test_normalizes_and_ranks_changes_deterministically(self) -> None:
        """Rank changes using the documented deterministic feature weights."""
        context = build_incident_context(self.source())
        self.assertEqual(context["incident_id"], "INC-1427")
        self.assertEqual(context["symptoms"]["error_rate"], 0.16)
        self.assertEqual(context["kubernetes_events"][0]["status"], 503)
        self.assertEqual(context["recent_changes"][0]["source"], "GitOps")
        self.assertEqual(context["recent_changes"][0]["rank"], "high")
        self.assertEqual(context["recent_changes"][-1]["rank"], "low")

    def test_keeps_dependency_and_trace_evidence_for_reasoning(self) -> None:
        """Retain non-change evidence needed for later reasoning."""
        context = build_incident_context(self.source())
        self.assertEqual(context["dependency_health"]["pricing-service"]["latency_ms"], 4800)
        self.assertIn("pricing-service", context["trace_findings"][0]["path"])
        self.assertIn("do not prove", context["correlation_method"]["note"])

    def test_rejects_a_change_without_trusted_feature_inputs(self) -> None:
        """Reject changes that lack their required relevance features."""
        raw = self.source()
        del raw["changes"][0]["affected_services"]
        with self.assertRaises(ValidationError):
            build_incident_context(raw)

    def test_rejects_non_object_source_records_with_validation_error(self) -> None:
        """Return a contract error for malformed event records."""
        raw = self.source()
        raw["kubernetes_events"] = ["not an event"]
        with self.assertRaisesRegex(ValidationError, "kubernetes_events"):
            build_incident_context(raw)

    def test_rejects_non_object_top_level_input(self) -> None:
        """Return a contract error when the source is not an object."""
        with self.assertRaisesRegex(ValidationError, "context source"):
            build_incident_context([])  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
