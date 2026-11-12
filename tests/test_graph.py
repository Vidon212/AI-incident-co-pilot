"""Exercise topology semantics, evidence quality, authorization, and graph-grounded RAG."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from incident_copilot.graph import graph_knowledge, query_graph
from incident_copilot.models import ValidationError
from incident_copilot.rollout import fingerprint


EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "graph"


def fixture(name):
    """Read an independent synthetic collector snapshot."""
    return json.loads((EXAMPLES / f"{name}.json").read_text(encoding="utf-8"))


class GraphTests(unittest.TestCase):
    """Verify graph traversal independently of interpretation or mutation policy."""

    def setUp(self):
        """Load the infrastructure-to-customer-path example."""
        self.graph = fixture("platform")
        self.query = fixture("database-impact")

    def review(self):
        """Query the current test snapshot."""
        return query_graph(self.graph, self.query)

    def test_terraform_impact_has_exact_shortest_evidence_path(self):
        """Walk upstream through resource ownership and downstream through callers."""
        packet = self.review()
        paths = {item["node_id"]: item["steps"] for item in packet["paths"]}
        self.assertEqual([step["to"] for step in paths["checkout-api"]],
                         ["inventory-sql", "inventory-db", "inventory-api", "checkout-api"])
        self.assertNotIn("pricing-api", paths)
        self.assertFalse(packet["mutation_authorized"])
        self.assertEqual({node["id"] for node in packet["nodes"] if node["kind"] == "SLO"},
                         {"checkout-availability"})
        self.assertIn("INC-892", {node["id"] for node in packet["nodes"]})
        self.assertNotIn("INC-892", paths)

    def test_dependencies_preserve_configured_and_observed_edges(self):
        """Observed calls supplement configuration without overwriting it."""
        self.query = fixture("checkout-dependencies")
        packet = self.review()
        inventory_calls = [edge for edge in packet["edges"]
                           if edge["from"] == "checkout-api" and edge["to"] == "inventory-api"]
        self.assertEqual({edge["basis"] for edge in inventory_calls}, {"configured", "observed"})
        self.assertNotIn("legacy-debug-service", {node["id"] for node in packet["nodes"]})
        self.assertIn({"edge_id": "edge-11", "reason": "low_confidence"}, packet["excluded_edges"])

    def test_weak_stale_future_and_sparse_observations_are_explained(self):
        """Filters retain uncertainty rather than silently promoting transient topology."""
        self.query = fixture("checkout-dependencies")
        for update, reason in [({"last_seen": "2026-11-10T12:00:00Z"}, "stale_relationship"),
                               ({"last_seen": "2026-11-12T12:00:00Z"}, "future_observation"),
                               ({"observations": 2}, "insufficient_observations")]:
            with self.subTest(reason=reason):
                graph = deepcopy(self.graph)
                graph["edges"][8].update(update)
                packet = query_graph(graph, self.query)
                self.assertIn({"edge_id": "edge-09", "reason": reason}, packet["excluded_edges"])
                self.assertNotIn("pricing-api", {node["id"] for node in packet["nodes"]})

    def test_threshold_equality_is_usable(self):
        """Freshness, confidence, and sample-count limits are inclusive."""
        edge = self.graph["edges"][8]
        edge.update(confidence=.8, observations=100, last_seen="2026-11-11T11:56:00Z")
        self.query = fixture("checkout-dependencies")
        self.assertIn("pricing-api", {node["id"] for node in self.review()["nodes"]})

    def test_cycles_terminate_and_do_not_cross_context_nodes(self):
        """A shared owner or historical incident must not connect unrelated services."""
        edge = deepcopy(self.graph["edges"][7])
        edge.update(id="cycle", **{"from": "inventory-api", "to": "checkout-api"})
        self.graph["edges"].append(edge)
        self.graph["edges"].append({**self.graph["edges"][14], "id": "shared-owner",
                                    "from": "pricing-api"})
        packet = self.review()
        self.assertEqual(len(packet["paths"]), 5)
        self.assertNotIn("pricing-api", {node["id"] for node in packet["nodes"]})

    def test_scope_denial_removes_nodes_edges_and_paths(self):
        """Hidden facts must not appear even in exclusion diagnostics."""
        self.graph["nodes"][2]["required_scopes"].append("restricted")
        packet = self.review()
        self.assertNotIn("inventory-api", json.dumps(packet))
        self.assertNotIn("edge-12", json.dumps(packet))
        self.query["root"] = "inventory-api"
        with self.assertRaises(ValidationError):
            self.review()

    def test_edge_scope_denial_does_not_announce_hidden_edge(self):
        """Per-edge access applies independently from node visibility."""
        self.graph["edges"][11]["required_scopes"].append("restricted")
        self.assertNotIn("edge-12", json.dumps(self.review()))

    def test_depth_node_and_annotation_limits_are_explicit(self):
        """Partial results cannot masquerade as a complete neighborhood."""
        for update in ({"max_hops": 2}, {"max_nodes": 2}, {"max_nodes": 5}):
            with self.subTest(update=update):
                self.query.update(update)
                packet = self.review()
                self.assertTrue(packet["truncated"])
                self.assertEqual(packet["decision"], "bounded_context")
                self.assertLessEqual(len(packet["nodes"]), self.query["max_nodes"])
                self.query = fixture("database-impact")

    def test_invalid_topology_is_rejected(self):
        """Malformed identity, relationship type, or provenance never reaches traversal."""
        for update in ({"from": "missing"}, {"relationship": "APPROVES"},
                       {"to": "commerce-team"}, {"confidence": True},
                       {"observations": 0}, {"confidence": float("nan")},
                       {"basis": "historical"}, {"required_scopes": []},
                       {"last_seen": "2026-11-11"}):
            with self.subTest(update=update):
                graph = deepcopy(self.graph)
                graph["edges"][0].update(update)
                with self.assertRaises(ValidationError):
                    query_graph(graph, self.query)

    def test_duplicates_and_query_environment_or_limits_are_rejected(self):
        """Snapshot ambiguity and cross-environment queries fail closed."""
        for key in ("nodes", "edges"):
            graph = deepcopy(self.graph)
            graph[key].append(deepcopy(graph[key][0]))
            with self.assertRaises(ValidationError):
                query_graph(graph, self.query)
        for update in ({"environment": "staging"}, {"max_hops": 11}, {"max_nodes": 501},
                       {"granted_scopes": []}, {"min_confidence": -1}):
            with self.subTest(update=update), self.assertRaises(ValidationError):
                query_graph(self.graph, {**self.query, **update})

    def test_graph_rag_selects_services_and_preserves_retrieval_policy(self):
        """Graph relevance cannot bypass authority and document access controls."""
        documents = fixture("documents")
        documents[0]["required_scopes"].append("restricted")
        packet = graph_knowledge(self.graph, self.query, documents,
                                 "What depends on this database?")
        results = {item["service"]: item["result"] for item in packet["knowledge"]}
        self.assertEqual(set(results), {"inventory-api", "checkout-api"})
        self.assertEqual(results["inventory-api"]["decision"], "insufficient_context")
        self.assertEqual(results["checkout-api"]["decision"], "grounded")
        self.assertNotIn("content", results["checkout-api"]["sources"][0])
        recorded = packet.pop("packet_sha256")
        self.assertEqual(recorded, fingerprint(packet))

    def test_results_are_repeatable_and_inputs_are_unchanged(self):
        """Queries are read-only and bind the exact graph, query, and output."""
        before = deepcopy(self.graph)
        self.assertEqual(self.review(), self.review())
        self.assertEqual(self.graph, before)
        self.assertEqual(self.review()["graph_sha256"], fingerprint(self.graph))

    def test_forward_manages_and_reverse_provisioning_find_same_consumers(self):
        """Equivalent explicit ownership conventions preserve impact direction."""
        expected = {item["node_id"] for item in self.review()["paths"]}
        edge = self.graph["edges"][13]
        edge["relationship"] = "PROVISIONED_BY"
        self.assertEqual({item["node_id"] for item in self.review()["paths"]}, expected)
        edge.update(relationship="MANAGES", **{"from": "inventory-tf", "to": "inventory-sql"})
        self.assertEqual({item["node_id"] for item in self.review()["paths"]}, expected)

    def test_historical_context_must_not_be_future_or_low_confidence(self):
        """Age exemption for history is not an exemption from all evidence filters."""
        self.graph["edges"][-1]["confidence"] = .1
        self.assertNotIn("INC-892", {node["id"] for node in self.review()["nodes"]})
        self.graph["edges"][-1].update(confidence=1, last_seen="2026-11-12T12:00:00Z")
        self.assertNotIn("INC-892", {node["id"] for node in self.review()["nodes"]})

    def test_empty_neighborhood_preserves_coverage_limit(self):
        """A graph with no edges reports its bounds rather than declaring no risk."""
        self.graph["edges"] = []
        packet = self.review()
        self.assertEqual(len(packet["nodes"]), 1)
        self.assertEqual(packet["coverage"], "snapshot_only")
        self.assertFalse(packet["mutation_authorized"])

    def test_cli_truncation_and_invalid_contract_exit_codes(self):
        """Automation distinguishes partial context from input rejection."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "query.json"
            for update, expected in [({"max_nodes": 1}, 1), ({"merge_authorized": True}, 2)]:
                with self.subTest(update=update):
                    path.write_text(json.dumps({**self.query, **update}), encoding="utf-8")
                    result = subprocess.run([sys.executable, "-m", "incident_copilot.graph_cli",
                                             "--graph", str(EXAMPLES / "platform.json"),
                                             "--query", str(path)], capture_output=True,
                                            text=True, check=False)
                    self.assertEqual(result.returncode, expected, result.stderr)

    def test_cli_published_example(self):
        """The documented command returns a parseable read-only context artifact."""
        result = subprocess.run([sys.executable, "-m", "incident_copilot.graph_cli", "--graph",
                                 str(EXAMPLES / "platform.json"), "--query",
                                 str(EXAMPLES / "database-impact.json")],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["coverage"], "snapshot_only")
