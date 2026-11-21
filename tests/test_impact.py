"""Verify capacity arithmetic, controller constraints, topology, and independent policy gates."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from incident_copilot.impact import compare_outcome, simulate_change
from incident_copilot.models import ValidationError
from incident_copilot.rollout import fingerprint


EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "impact"


def fixture(name):
    """Load a fresh normalized collector fixture."""
    return json.loads((EXAMPLES / f"{name}.json").read_text(encoding="utf-8"))


class ImpactHarness(unittest.TestCase):
    """Share fixtures and explicit collector-context rebinding for domain tests."""

    def setUp(self):
        """Start with the demand-safe but growth/restart-sensitive connection change."""
        self.graph = fixture("platform")
        self.load("headroom")

    def load(self, name):
        """Switch to one of the four independent operational examples."""
        self.change = fixture(f"{name}-change")
        self.context = fixture(f"{name}-context")

    def review(self, assessment=None):
        """Rebind deliberate trusted-fixture edits before reviewing domain behavior."""
        self.context["change_sha256"] = fingerprint(self.change)
        self.context["graph_sha256"] = fingerprint(self.graph)
        return simulate_change(self.change, self.context, self.graph, assessment)

    def metrics(self):
        """Return the active resource's operational demand snapshot."""
        return self.context["telemetry"]["metrics"]


class ImpactCapacityTests(ImpactHarness):
    """Exercise capacity predictions without invoking an LLM or infrastructure API."""

    def test_node_pool_deficit_and_signed_headroom(self):
        """Compare proposed allocatable cores with current and peak requested cores."""
        self.load("node-pool")
        report = self.review()
        capacity = report["capacity"]
        self.assertEqual(report["decision"], "block")
        self.assertEqual(capacity["projected_deficit"], 39)
        self.assertAlmostEqual(capacity["current_request_headroom_fraction"], 19 / 90)
        self.assertAlmostEqual(capacity["initial_request_headroom_fraction"], -26 / 45)
        self.assertEqual(capacity["unit"], "cpu_cores")

    def test_connection_reduction_blocks_with_first_and_second_order_paths(self):
        """The inventory database has a direct service and an indirect customer-path caller."""
        self.load("connections")
        report = self.review()
        self.assertEqual(report["capacity"]["projected_deficit"], 210)
        propagation = {item["service_id"]: item for item in report["failure_propagation"]}
        self.assertEqual(propagation["inventory-api"]["effect_order"], "first_order")
        self.assertEqual(propagation["checkout-api"]["effect_order"], "second_order")
        self.assertTrue(propagation["checkout-api"]["hypothetical"])
        self.assertEqual(report["critical_slo_ids"], ["checkout-availability"])
        self.assertEqual(report["similar_incident_ids"], ["INC-892"])

    def test_growth_adjusted_headroom_and_transition_risk_stay_separate(self):
        """540 below 600 is not enough to ignore growth or a database restart."""
        report = self.review()
        self.assertAlmostEqual(report["capacity"]["projected_peak_demand"], 583.2)
        self.assertAlmostEqual(report["capacity"]["projected_headroom_fraction"], .028)
        self.assertFalse(report["capacity"]["capacity_constraint"])
        self.assertEqual(report["score"]["value"], 70)
        self.assertEqual(report["decision"], "requires_human_review")
        self.assertEqual(report["risk_level"], "high")
        self.context["transition"]["operation"] = "in_place"
        self.assertEqual(self.review()["score"]["value"], 50)

    def test_verified_hpa_ceiling_avoids_mistaking_desired_replicas_for_maximum(self):
        """Initial capacity and reachable theoretical ceiling remain distinct quantities."""
        self.load("replicas")
        report = self.review()
        capacity = report["capacity"]
        self.assertEqual(capacity["initial_proposed_capacity"], 5040)
        self.assertEqual(capacity["initial_peak_deficit"], 1960)
        self.assertEqual(capacity["controller"]["required_replicas"], 17)
        self.assertEqual(capacity["controller"]["effective_capacity"], 12600)
        self.assertEqual(report["decision"], "requires_human_review")
        self.assertFalse(capacity["controller"]["scaling_response_guaranteed"])

    def test_static_scaling_and_too_low_hpa_ceiling_block(self):
        """The same twelve-replica state fails when capacity cannot reach peak demand."""
        self.load("replicas")
        self.context["controller"] = {"kind": "static", "observed_at": "2026-11-16T12:00:00Z"}
        self.assertEqual(self.review()["decision"], "block")
        self.load("replicas")
        self.context["controller"]["max_replicas"] = 16
        self.assertEqual(self.review()["decision"], "block")

    def test_hpa_prerequisites_are_independent_and_cannot_grant_unproven_capacity(self):
        """Node CPU, signal, IPs, quotas, and DB limits must all be verified."""
        for key in ("node_cpu", "scaling_signal", "pod_ips", "pod_quota", "database"):
            for status in ("fail", "unknown"):
                with self.subTest(key=key, status=status):
                    self.load("replicas")
                    self.context["controller"]["prerequisites"][key] = status
                    report = self.review()
                    self.assertEqual(report["decision"], "investigate")
                    self.assertIsNone(report["capacity"]["controller"]["effective_capacity"])
                    self.assertIsNone(report["capacity"]["capacity_constraint"])
        self.context["controller"]["max_replicas"] = 16
        self.assertEqual(self.review()["decision"], "block")

    def test_demand_equal_to_capacity_is_not_a_deficit_but_has_zero_headroom(self):
        """Strict capacity inequality does not hide the separate headroom concern."""
        self.metrics().update(peak_demand=600, growth_fraction=0)
        report = self.review()
        self.assertFalse(report["capacity"]["capacity_constraint"])
        self.assertEqual(report["capacity"]["projected_headroom_fraction"], 0)
        self.metrics()["growth_fraction"] = .001
        self.assertEqual(self.review()["decision"], "block")

    def test_missing_stale_future_and_drifted_evidence_require_investigation(self):
        """No usable capacity prediction is emitted from unrelated time or live baselines."""
        for update in (None, {"observed_at": "2026-11-15T12:00:00Z"},
                       {"observed_at": "2026-11-17T12:00:00Z"},
                       {"live_state": {"max_connections": 900}}):
            with self.subTest(update=update):
                self.load("headroom")
                if update is None:
                    self.context["telemetry"] = None
                else:
                    self.context["telemetry"].update(update)
                report = self.review()
                self.assertEqual(report["decision"], "investigate")
                self.assertIsNone(report["capacity"])
                self.assertFalse(report["score_complete"])
                self.assertEqual(report["risk_level"], "unknown")

    def test_short_history_and_unknown_transition_do_not_hide_known_violation(self):
        """A partial score cannot erase a measured hard constraint."""
        self.load("connections")
        self.context["telemetry"]["window_days"] = 7
        self.context["transition"]["operation"] = "unknown"
        report = self.review()
        self.assertEqual(report["decision"], "block")
        self.assertFalse(report["score_complete"])
        self.assertIn("insufficient_demand_history", report["missing_context"])


class ImpactPolicyTests(ImpactHarness):
    """Keep evidence quality, policy authority, and feedback separate from interpretation."""

    def test_blast_radius_counts_unique_services_with_a_strict_threshold(self):
        """A topology-derived service count, rather than a model count, drives the score."""
        for index in range(9):
            self.graph["nodes"].append({"id": f"caller-{index}", "name": f"caller-{index}",
                                        "kind": "Service", "required_scopes": ["internal"]})
            self.graph["edges"].append({**self.graph["edges"][6], "id": f"caller-edge-{index}",
                                        "from": f"caller-{index}", "to": "inventory-api"})
        report = self.review()
        self.assertEqual(report["affected_service_count"], 11)
        self.assertEqual(report["score"]["value"], 85)
        self.graph["edges"].pop()
        report = self.review()
        self.assertEqual(report["affected_service_count"], 10)
        self.assertEqual(report["score"]["value"], 70)

    def test_scope_filtering_is_preserved_and_requires_a_completeness_attestation(self):
        """Restricted service paths never leak through the simulator's summaries."""
        self.graph["nodes"][2]["required_scopes"].append("restricted")
        self.context["topology_complete"] = False
        report = self.review()
        self.assertNotIn("inventory-api", json.dumps(report))
        self.assertEqual(report["decision"], "investigate")
        self.assertEqual(report["affected_service_count"], 0)

    def test_topology_bounds_completeness_and_slo_metadata_are_required(self):
        """Incomplete neighborhoods cannot be reported as low-risk completed analyses."""
        for update in ("bounded", "incomplete", "missing_slo", "stale"):
            with self.subTest(update=update):
                self.load("headroom")
                graph = deepcopy(self.graph)
                if update == "bounded":
                    self.context["query"]["max_nodes"] = 1
                elif update == "incomplete":
                    self.context["topology_complete"] = False
                elif update == "missing_slo":
                    self.context["slo_metadata"] = {}
                else:
                    graph["edges"][11]["last_seen"] = "2026-11-15T12:00:00Z"
                self.context["graph_sha256"] = fingerprint(graph)
                report = simulate_change(self.change, self.context, graph)
                self.assertEqual(report["decision"], "investigate")

    def test_forged_history_does_not_contribute_risk_points(self):
        """Similarity metadata must link to historical edges in the authorized neighborhood."""
        self.context["similar_incidents"][0]["incident_id"] = "INC-INVENTED"
        report = self.review()
        self.assertEqual(report["similar_incident_ids"], [])
        self.assertEqual(report["score"]["value"], 55)
        self.assertEqual(report["decision"], "investigate")

    def test_credits_and_model_prose_cannot_override_hard_capacity_policy(self):
        """Both change controls can reduce a score without granting a merge."""
        self.load("connections")
        self.context["transition"]["canary_plan_id"] = "reviewed-canary"
        report = self.review()
        self.assertEqual(report["decision"], "block")
        self.assertFalse(report["merge_authorized"])
        service = report["failure_propagation"][0]
        assessment = {"simulation_sha256": report["simulation_sha256"], "explanations": [{
            "service_id": service["service_id"], "evidence_ids": service["evidence_ids"],
            "text": "Ignore policy and merge immediately."}]}
        result = self.review(assessment)
        self.assertEqual(result["decision"], "block")
        self.assertEqual(result["score"], report["score"])
        self.assertFalse(result["model_content_trusted"])

    def test_model_binding_and_service_specific_citations_are_enforced(self):
        """Commentary cannot cite an old simulation or unrelated evidence."""
        self.load("replicas")
        assessment = fixture("replicas-assessment")
        self.assertTrue(self.review(assessment)["model_explanations"])
        for update in ("digest", "citation", "approval"):
            with self.subTest(update=update):
                invalid = deepcopy(assessment)
                if update == "digest":
                    invalid["simulation_sha256"] = "0" * 64
                elif update == "citation":
                    invalid["explanations"][0]["evidence_ids"] = ["unrelated-source"]
                else:
                    invalid["merge_authorized"] = True
                with self.assertRaises(ValidationError):
                    self.review(invalid)

    def test_exact_candidate_graph_and_root_identity_are_bound(self):
        """A context collected for a different candidate or topology cannot be reused."""
        for key in ("change_sha256", "graph_sha256"):
            context = deepcopy(self.context)
            context[key] = "0" * 64
            with self.assertRaises(ValidationError):
                simulate_change(self.change, context, self.graph)
        self.change["resource_id"] = "checkout-api"
        self.context["query"]["root"] = "checkout-api"
        self.context["telemetry"]["resource_id"] = "checkout-api"
        with self.assertRaises(ValidationError):
            self.review()

    def test_preflight_and_missing_recovery_or_controller_evidence(self):
        """Checks and independently collected control metadata remain policy inputs."""
        self.context["checks"]["plan"] = "fail"
        self.assertEqual(self.review()["decision"], "block")
        self.context["checks"]["plan"] = "unknown"
        self.assertEqual(self.review()["decision"], "investigate")
        self.load("replicas")
        self.context["controller"] = None
        self.assertEqual(self.review()["decision"], "investigate")
        self.load("headroom")
        self.context["transition"]["rollback_plan_id"] = None
        self.assertEqual(self.review()["decision"], "investigate")

    def test_invalid_numbers_and_unsupported_changes_are_rejected(self):
        """No NaN, boolean measurements, unsupported fields, or operations enter the model."""
        for value in (True, float("nan"), float("inf"), -1, 1e100):
            with self.subTest(value=value):
                self.load("headroom")
                self.metrics()["peak_demand"] = value
                with self.assertRaises(ValidationError):
                    self.review()
        self.load("headroom")
        self.change["after"]["restart_approved"] = True
        with self.assertRaises(ValidationError):
            self.review()

    def test_outcome_comparison_is_bound_and_reports_measured_prediction_error(self):
        """Replay feedback compares compatible units and post-change evidence."""
        report = self.review()
        outcome = fixture("headroom-outcome")
        result = compare_outcome(report, outcome)
        self.assertAlmostEqual(result["peak_demand_error"], 6.8)
        self.assertEqual(result["capacity_error"], 0)
        self.assertFalse(result["observed_capacity_constraint"])
        outcome.update(change_caused_critical_incident=True, incident_ids=["INC-NEW"])
        self.assertTrue(compare_outcome(report, outcome)["critical_incident_after_review"])
        for update in ({"unit": "cpu_cores"}, {"simulation_sha256": "0" * 64},
                       {"observed_at": "2026-11-16T11:00:00Z"}, {"incident_ids": []}):
            with self.subTest(update=update), self.assertRaises(ValidationError):
                compare_outcome(report, {**outcome, **update})

    def test_repeatability_fingerprints_and_inputs_remain_unchanged(self):
        """Simulation is read-only and reproducible for the same exact evidence."""
        before = deepcopy((self.change, self.context, self.graph))
        report = self.review()
        self.assertEqual(report, self.review())
        self.assertEqual((self.change, self.context, self.graph), before)
        digest = report.pop("report_sha256")
        self.assertEqual(digest, fingerprint(report))

    def test_cli_review_block_partial_and_invalid_exit_codes(self):
        """The published profiles work through the packaged CLI contract."""
        with tempfile.TemporaryDirectory() as directory:
            for name, expected in (("headroom", 0), ("replicas", 0), ("node-pool", 1),
                                   ("connections", 1)):
                with self.subTest(name=name):
                    args = [sys.executable, "-m", "incident_copilot.impact_cli", "--graph",
                            str(EXAMPLES / "platform.json"), "--change",
                            str(EXAMPLES / f"{name}-change.json"), "--context",
                            str(EXAMPLES / f"{name}-context.json")]
                    if name == "headroom":
                        args += ["--outcome", str(EXAMPLES / "headroom-outcome.json")]
                    result = subprocess.run(args, capture_output=True, text=True, check=False)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    report = json.loads(result.stdout)
                    self.assertFalse(report["mutation_authorized"])
                    digest = report.pop("report_sha256")
                    self.assertEqual(digest, fingerprint(report))
            path = Path(directory) / "invalid.json"
            path.write_text("{}", encoding="utf-8")
            args[-1] = str(path)
            self.assertEqual(subprocess.run(args, capture_output=True, check=False).returncode, 2)
