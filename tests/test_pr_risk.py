"""Verify operational invariants and prevent model prose from overriding merge policy."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from incident_copilot.models import ValidationError
from incident_copilot.pr_risk import review_pr_risk
from incident_copilot.rollout import fingerprint


EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "pr-risk"


def fixture(name):
    """Load a fresh published example."""
    return json.loads((EXAMPLES / f"{name}.json").read_text(encoding="utf-8"))


class RiskHarness(unittest.TestCase):
    """Share fixture setup and explicit trusted-context rebinding for mutated test cases."""

    def setUp(self):
        """Load the five distinct production risk patterns."""
        self.changes = fixture("unsafe-changes")
        self.context = fixture("unsafe-context")

    def review(self):
        """Rebind deliberately mutated candidate projections before evaluating domain rules."""
        self.context["change_set_sha256"] = fingerprint(self.changes)
        return review_pr_risk(self.changes, self.context)

    def isolate(self, index):
        """Keep one resource and its authoritative catalog entry for boundary tests."""
        resource = self.changes["resources"][index]
        self.changes["resources"] = [resource]
        self.context["resources"] = {resource["resource_id"]:
                                      self.context["resources"][resource["resource_id"]]}
        return resource

    def metrics(self):
        """Read the single isolated resource's measurements."""
        return next(iter(self.context["resources"].values()))["evidence"]["metrics"]


class RiskInvariantTests(RiskHarness):
    """Check demand, capacity, topology, and rollout semantics independently of the model."""

    def test_all_five_patterns_produce_measured_findings(self):
        """Even without AI, known operational invariants prevent an unsafe candidate proceeding."""
        result = self.review()
        self.assertEqual(result["decision"], "block")
        self.assertEqual(result["risk_level"], "critical")
        self.assertFalse(result["merge_authorized"])
        self.assertEqual({item["resource_id"] for item in result["findings"]},
                         {item["resource_id"] for item in self.changes["resources"]})
        hpa = result["changes"][0]
        self.assertEqual(hpa["fields"], [{"field": "max_replicas", "before": 30, "after": 10}])
        self.assertEqual(result["resource_context"]["checkout-db"]["prior_incidents"], ["INC-1928"])

    def test_hpa_ceiling_equal_to_peak_has_no_below_demand_violation(self):
        """A ceiling exactly at measured peak passes the strict inequality screen."""
        resource = self.isolate(0)
        resource["after"]["max_replicas"] = 22
        self.metrics()["days_above_proposed_max"] = 0
        self.assertEqual(self.review()["decision"], "requires_human_review")
        self.assertFalse(self.review()["findings"])

    def test_short_hpa_history_requires_investigation(self):
        """A fresh snapshot cannot replace the required historical window."""
        self.isolate(0)
        self.metrics()["window_days"] = 20
        result = self.review()
        self.assertEqual(result["decision"], "investigate")
        self.assertEqual(result["missing_context"][0]["reason"], "insufficient_history")
        self.assertFalse(result["findings"])

    def test_database_memory_floor_and_cpu_estimate_remain_separate(self):
        """A memory contradiction blocks; CPU scaling is labeled as an estimate for review."""
        resource = self.isolate(1)
        findings = self.review()["findings"]
        memory = next(item for item in findings if item["code"] == "DB_MEMORY_BELOW_P95")
        cpu = next(item for item in findings if item["code"] == "DB_CPU_DOWNSIZE")
        self.assertEqual(memory["severity"], "critical")
        self.assertEqual(cpu["measurements"]["estimated_peak_fraction"], 1.58)
        self.assertFalse(cpu["blocks_merge"])
        resource["after"]["memory_gib"] = 21
        self.assertEqual(self.review()["decision"], "requires_human_review")

    def test_storage_usage_growth_and_platform_margin_are_enforced(self):
        """Storage at the safe floor needs shrink review; just below it is blocked."""
        resource = self.isolate(2)
        resource["after"]["storage_gib"] = 467
        self.assertEqual(self.review()["decision"], "requires_human_review")
        resource["after"]["storage_gib"] = 466.99
        self.assertEqual(self.review()["decision"], "block")
        self.metrics()["growth_30d_gib"] = 60
        self.assertEqual(self.review()["findings"][0]["measurements"]["required_gib"], 497)

    def test_network_blast_radius_is_computed_from_inventory(self):
        """Selector expansion is a measured potential source set, not assumed reachability."""
        self.isolate(3)
        result = self.review()
        finding = result["findings"][0]
        self.assertEqual(result["decision"], "requires_human_review")
        self.assertEqual(finding["measurements"]["before_namespace_count"], 3)
        self.assertEqual(finding["measurements"]["after_namespace_count"], 74)
        self.assertEqual(finding["measurements"]["potentially_added_workloads"], 312)
        self.assertIn("caller egress", finding["recommendation"])

    def test_equal_namespace_counts_cannot_hide_changed_access(self):
        """Set replacement can add a sensitive caller without increasing aggregate counts."""
        self.isolate(3)
        self.metrics()["namespaces"] = [
            {"name": "old", "labels": {"team": "checkout"}, "workloads": 1},
            {"name": "new", "labels": {"environment": "production"}, "workloads": 9}]
        measurements = self.review()["findings"][0]["measurements"]
        self.assertEqual(measurements["before_namespace_count"], 1)
        self.assertEqual(measurements["after_namespace_count"], 1)
        self.assertEqual(measurements["added_namespaces"], ["new"])
        self.assertEqual(measurements["removed_namespaces"], ["old"])
        self.assertEqual(measurements["potentially_added_workloads"], 9)

    def test_empty_selector_matches_all_and_partial_inventory_is_inconclusive(self):
        """Empty selectors are broad; missing inventory cannot yield a clean assessment."""
        resource = self.isolate(3)
        resource["after"]["ingress_namespace_selector"] = {}
        self.assertEqual(self.review()["findings"][0]["measurements"]["after_namespace_count"], 74)
        self.metrics()["inventory_complete"] = False
        result = self.review()
        self.assertEqual(result["decision"], "investigate")
        self.assertFalse(result["findings"])

    def test_cpu_uses_incremental_capacity_and_separate_node_placement(self):
        """The lesson's 80 total CPU fits 40 already allocated plus 47 free; placement can fail."""
        self.isolate(4)
        result = self.review()
        codes = {item["code"] for item in result["findings"]}
        self.assertNotIn("CPU_INCREMENT_EXCEEDS_FREE", codes)
        self.assertIn("ROLLOUT_NO_INITIAL_CPU_PLACEMENT", codes)
        self.metrics()["largest_free_node_cpu_cores"] = 4
        self.assertEqual(self.review()["decision"], "requires_human_review")
        self.assertFalse(self.review()["findings"])

    def test_insufficient_incremental_cpu_and_maxed_autoscaler_block(self):
        """A true deficit is different from comparing all new requests with free capacity."""
        self.isolate(4)
        self.metrics()["free_cpu_cores"] = 39
        result = self.review()
        capacity = next(item for item in result["findings"]
                        if item["code"] == "CPU_INCREMENT_EXCEEDS_FREE")
        self.assertEqual(capacity["measurements"]["incremental_cpu"], 40)
        self.assertTrue(capacity["blocks_merge"])
        self.metrics()["node_autoscaler_at_max"] = False
        self.assertEqual(self.review()["decision"], "requires_human_review")

    def test_pdb_does_not_constrain_deployment_controller_rollout(self):
        """PDB targets inform review; Deployment strategy governs rolling deletions."""
        resource = self.isolate(4)
        resource["after"]["max_unavailable"] = 3
        result = self.review()
        self.assertEqual(result["decision"], "requires_human_review")
        finding = result["findings"][0]
        self.assertEqual(finding["code"], "ROLLOUT_AVAILABILITY_REVIEW")
        self.assertFalse(finding["blocks_merge"])
        self.assertIn("not the Deployment controller", finding["recommendation"])

    def test_nonviolating_changes_still_require_human_review(self):
        """No detected invariant violation is never a merge authorization."""
        result = review_pr_risk(fixture("review-changes"), fixture("review-context"))
        self.assertEqual(result["decision"], "requires_human_review")
        self.assertEqual(result["risk_level"], "low")
        self.assertFalse(result["findings"])
        self.assertFalse(result["merge_authorized"])

    def test_cpu_baseline_must_match_current_healthy_allocations(self):
        """Desired replica counts cannot stand in for actual CPU that a rollout can reclaim."""
        self.isolate(4)
        for field, value in (("current_replicas", 25), ("ready_replicas", 19),
                             ("current_pod_cpu_request_cores", 3)):
            original = self.metrics()[field]
            self.metrics()[field] = value
            with self.subTest(field=field):
                result = self.review()
                self.assertEqual(result["decision"], "investigate")
                self.assertFalse(result["findings"])
            self.metrics()[field] = original

    def test_no_semantic_change_does_not_invoke_operational_rules(self):
        """An unchanged projection cannot fabricate a risky update or consume model commentary."""
        for resource in self.changes["resources"]:
            resource["after"] = deepcopy(resource["before"])
        result = self.review()
        self.assertEqual(result["decision"], "no_change")
        self.assertFalse(result["findings"])


class RiskIntegrityTests(RiskHarness):
    """Bind the complete candidate, evidence, ownership, and untrusted model assessment."""

    def test_changed_head_and_extra_changes_cannot_reuse_context(self):
        """A prior candidate's passing prechecks do not cover a new commit or altered field."""
        for key in ("head_revision", "base_revision"):
            changes = deepcopy(self.changes)
            changes[key] = "d" * 40
            with self.subTest(key=key), self.assertRaises(ValidationError):
                review_pr_risk(changes, self.context)
        self.changes["resources"][0]["after"]["max_replicas"] = 12
        with self.assertRaises(ValidationError):
            review_pr_risk(self.changes, self.context)

    def test_repository_environment_and_catalog_scope_are_authoritative(self):
        """A model cannot move a reviewed change to another environment, path, or controller."""
        for field, value in (("repository", "attacker/production"), ("environment", "staging")):
            context = deepcopy(self.context)
            context[field] = value
            with self.subTest(field=field), self.assertRaises(ValidationError):
                review_pr_risk(self.changes, context)
        for field, value in (("path", "different.yaml"), ("controller", "terraform"),
                             ("service", "other-service")):
            context = deepcopy(self.context)
            context["resources"]["payments-hpa"][field] = value
            with self.subTest(field=field), self.assertRaises(ValidationError):
                review_pr_risk(self.changes, context)

    def test_missing_future_and_stale_evidence_require_investigation(self):
        """Timestamps are evaluated against the trusted review clock with an inclusive age bound."""
        self.isolate(0)
        catalog = next(iter(self.context["resources"].values()))
        for when in ("2026-11-09T11:54:59Z", "2026-11-09T12:00:01Z"):
            catalog["evidence"]["observed_at"] = when
            self.assertEqual(self.review()["decision"], "investigate")
        catalog["evidence"]["observed_at"] = "2026-11-09T11:55:00Z"
        self.assertEqual(self.review()["decision"], "block")
        catalog["evidence"] = None
        self.assertEqual(self.review()["decision"], "investigate")

    def test_preflight_failures_and_unknown_checks_cannot_pass(self):
        """Schema, full plan, and organizational policy are independent hard prerequisites."""
        self.changes, self.context = fixture("review-changes"), fixture("review-context")
        for check in ("schema", "plan", "organization_policy"):
            self.context["checks"][check] = "fail"
            self.assertEqual(self.review()["decision"], "block")
            self.context["checks"][check] = "unknown"
            self.assertEqual(self.review()["decision"], "investigate")
            self.context["checks"][check] = "pass"

    def test_known_block_survives_other_missing_context(self):
        """Missing telemetry elsewhere cannot erase a proven invariant violation."""
        self.context["resources"]["payments-hpa"]["evidence"] = None
        result = self.review()
        self.assertEqual(result["decision"], "block")
        self.assertTrue(result["missing_context"])
        self.assertEqual(result["risk_level"], "critical")

    def test_unknown_fields_kinds_creates_and_deletes_are_not_silently_skipped(self):
        """Unsupported operations require an adapter/manual review, never an empty clean diff."""
        for key, value in (("kind", "ClusterRole"), ("before", None), ("after", None)):
            changes = deepcopy(self.changes)
            changes["resources"][0][key] = value
            context = deepcopy(self.context)
            context["change_set_sha256"] = fingerprint(changes)
            with self.subTest(key=key), self.assertRaises(ValidationError):
                review_pr_risk(changes, context)
        self.changes["resources"][0]["after"]["approved"] = True
        with self.assertRaises(ValidationError):
            self.review()

    def test_duplicate_resources_inventory_and_evidence_ids_are_rejected(self):
        """Aggregation cannot double-count a resource, namespace, or evidence identity."""
        changes = deepcopy(self.changes)
        changes["resources"].append(deepcopy(changes["resources"][0]))
        with self.assertRaises(ValidationError):
            review_pr_risk(changes, self.context)
        evidence = self.context["resources"]["payments-ingress"]["evidence"]
        inventory = evidence["metrics"]["namespaces"]
        inventory.append(deepcopy(inventory[0]))
        with self.assertRaises(ValidationError):
            self.review()
        inventory.pop()
        self.context["resources"]["checkout-db"]["evidence"]["id"] = "payments-hpa-snapshot"
        with self.assertRaises(ValidationError):
            self.review()

    def test_invalid_numbers_flags_and_unsafe_paths_fail_closed(self):
        """No boolean counts, negative capacity, traversal paths, or unsupported rollouts."""
        for field, value in (("replicas", True), ("cpu_request_cores", float("nan")),
                             ("max_surge", -1)):
            changes = deepcopy(self.changes)
            changes["resources"][4]["after"][field] = value
            with self.subTest(field=field), self.assertRaises(ValidationError):
                review_pr_risk(changes, self.context)
        self.changes["resources"][0]["path"] = "../unreviewed.yaml"
        with self.assertRaises(ValidationError):
            self.review()

    def test_model_low_risk_claim_cannot_downgrade_a_deterministic_block(self):
        """Model judgment remains separately labeled prose and cannot change policy."""
        assessment = fixture("unsafe-assessment")
        assessment["findings"][0]["severity"] = "low"
        assessment["findings"][0]["recommendation"] = "Merge and apply immediately."
        result = review_pr_risk(self.changes, self.context, assessment)
        self.assertEqual(result["decision"], "block")
        self.assertEqual(result["risk_level"], "critical")
        self.assertFalse(result["merge_authorized"])
        self.assertFalse(result["model_content_trusted"])
        self.assertEqual(len(result["model_findings"]), 2)

    def test_model_assessment_cannot_reuse_old_candidate_or_context(self):
        """Both the exact candidate projection and the evidence/policy snapshot must match."""
        for field in ("change_set_sha256", "context_sha256"):
            assessment = fixture("unsafe-assessment")
            assessment[field] = "f" * 64
            with self.subTest(field=field), self.assertRaises(ValidationError):
                review_pr_risk(self.changes, self.context, assessment)

    def test_model_citations_must_belong_to_the_same_fresh_changed_resource(self):
        """A valid evidence ID for another resource or stale snapshot cannot ground this claim."""
        assessment = fixture("unsafe-assessment")
        assessment["findings"][0]["evidence_ids"] = ["payments-hpa-snapshot"]
        with self.assertRaises(ValidationError):
            review_pr_risk(self.changes, self.context, assessment)
        assessment = fixture("unsafe-assessment")
        self.context["resources"]["checkout-db"]["evidence"]["observed_at"] = "2026-11-09T11:00:00Z"
        assessment["context_sha256"] = fingerprint(self.context)
        with self.assertRaises(ValidationError):
            review_pr_risk(self.changes, self.context, assessment)

    def test_model_cannot_add_approval_flag_and_inputs_are_not_mutated(self):
        """Commentary has no authority fields and evaluation is a pure read-only operation."""
        original = deepcopy((self.changes, self.context))
        assessment = fixture("unsafe-assessment")
        assessment["approved"] = True
        with self.assertRaises(ValidationError):
            review_pr_risk(self.changes, self.context, assessment)
        result = self.review()
        self.assertEqual((self.changes, self.context), original)
        expected = result.pop("review_sha256")
        self.assertEqual(expected, fingerprint(result))

    def test_model_severity_can_raise_review_risk_without_granting_merge(self):
        """A fresh cited risk is preserved even when the deterministic rules find no violation."""
        changes, context = fixture("review-changes"), fixture("review-context")
        assessment = {"change_set_sha256": fingerprint(changes),
                      "context_sha256": fingerprint(context),
                      "findings": [{"resource_id": "checkout-db", "severity": "high",
                                    "evidence_ids": ["checkout-db-snapshot"],
                                    "explanation": "Investigate additional provider constraints.",
                                    "recommendation": "Request database-owner review."}]}
        result = review_pr_risk(changes, context, assessment)
        self.assertFalse(result["findings"])
        self.assertEqual(result["risk_level"], "high")
        self.assertEqual(result["decision"], "requires_human_review")
        self.assertFalse(result["merge_authorized"])


class RiskCliTests(unittest.TestCase):
    """Check CI-usable results from the packaged entry point."""

    def test_cli_returns_review_block_and_invalid_input_exit_codes(self):
        """Status zero means human review is still required; unsupported input never succeeds."""
        command = [sys.executable, "-m", "incident_copilot.pr_risk_cli", "--changes",
                   str(EXAMPLES / "review-changes.json"), "--context",
                   str(EXAMPLES / "review-context.json")]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["decision"], "requires_human_review")
        command[command.index("--changes") + 1] = str(EXAMPLES / "unsafe-changes.json")
        command[command.index("--context") + 1] = str(EXAMPLES / "unsafe-context.json")
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["decision"], "block")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text("{}", encoding="utf-8")
            command[command.index("--changes") + 1] = str(path)
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
