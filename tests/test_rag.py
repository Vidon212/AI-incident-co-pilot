"""Verify authority-aware retrieval, citations, access, and injection boundaries."""

from copy import deepcopy
import json
from pathlib import Path
import unittest

from incident_copilot.models import ValidationError
from incident_copilot.rag import retrieve_knowledge


ROOT = Path(__file__).parents[1]


def fixture(name):
    """Load one published RAG example."""
    with (ROOT / "examples" / "rag" / name).open(encoding="utf-8") as source:
        return json.load(source)


class RetrievalPolicyTests(unittest.TestCase):
    """Exercise authority, freshness, authorization, and contradiction policy."""

    def setUp(self):
        """Load the grounded checkout memory scenario."""
        self.query = fixture("checkout-memory-query.json")
        self.documents = fixture("checkout-memory-documents.json")

    def retrieve(self):
        """Retrieve the current checkout fixture state."""
        return retrieve_knowledge(self.query, self.documents)

    def test_authority_outweighs_high_similarity_chat(self):
        """Approved standards and runbooks outrank an extremely similar chat message."""
        result = self.retrieve()
        ids = [source["id"] for source in result.sources]
        self.assertEqual(result.decision, "grounded")
        self.assertEqual(ids[:2], ["checkout-runbook", "kubernetes-platform-standard"])
        self.assertNotIn("memory-slack-message", ids)

    def test_deprecated_and_unauthorized_sources_are_excluded(self):
        """Metadata policy filters sources before they can influence reasoning."""
        self.documents.append(fixture("database-contradiction-documents.json")[2])
        excluded = {item["id"]: item["reason"] for item in self.retrieve().excluded}
        self.assertEqual(excluded["restricted-security-standard"], "access_denied")
        self.assertEqual(excluded["deprecated-jenkins-process"], "deprecated")

    def test_raw_prompt_injection_is_not_in_context_packet(self):
        """Raw retrieved content never crosses into the structured reasoning packet."""
        result = self.retrieve()
        serialized = json.dumps(result.to_dict())
        self.assertNotIn("debug.example.com", serialized)
        self.assertNotIn("Ignore previous policies", serialized)
        self.assertIn("Raw retrieved content is untrusted", serialized)

    def test_sources_have_stable_citations_and_reviewed_facts(self):
        """Every selected source binds its facts to a version and review date."""
        for source in self.retrieve().sources:
            self.assertIn(source["id"], source["citation"])
            self.assertIn("@", source["citation"])
            self.assertTrue(source["facts"])

    def test_authoritative_contradiction_requires_investigation(self):
        """Current implementation and approved documentation cannot be resolved silently."""
        result = retrieve_knowledge(
            fixture("database-contradiction-query.json"),
            fixture("database-contradiction-documents.json"),
        )
        self.assertEqual(result.decision, "investigate")
        self.assertEqual(result.contradictions[0]["topic"],
                         "database.provisioning.method")
        self.assertEqual({item["value"] for item in result.contradictions[0]["values"]},
                         {"terraform", "crossplane"})

    def test_future_review_date_is_rejected(self):
        """A future timestamp cannot inflate source freshness."""
        self.documents[0]["last_reviewed"] = "2026-10-14"
        with self.assertRaises(ValidationError):
            self.retrieve()

    def test_environment_and_service_mismatches_are_filtered(self):
        """Similar documents for another target stay outside the context packet."""
        other = deepcopy(self.documents[0])
        other.update(id="other-service", service="billing-api", environment="staging")
        self.documents.append(other)
        excluded = {item["id"]: item["reason"] for item in self.retrieve().excluded}
        self.assertEqual(excluded["other-service"], "service_mismatch")

    def test_empty_result_is_insufficient_context(self):
        """No eligible evidence produces no answer rather than model guesswork."""
        query = deepcopy(self.query)
        query["granted_scopes"] = []
        result = retrieve_knowledge(query, self.documents)
        self.assertEqual(result.decision, "insufficient_context")
        self.assertFalse(result.sources)

    def test_malformed_candidates_are_rejected(self):
        """Extra authority, invalid scores, and malformed facts fail validation."""
        changes = (
            {"authority": 1.0},
            {"similarity": 1.1},
            {"facts": [{"topic": "memory.target", "value": [], "kind": "recommendation"}]},
            {"required_scopes": ["internal", "internal"]},
        )
        for change in changes:
            with self.subTest(change=change):
                documents = deepcopy(self.documents)
                documents[0].update(change)
                with self.assertRaises(ValidationError):
                    retrieve_knowledge(self.query, documents)


if __name__ == "__main__":
    unittest.main()
