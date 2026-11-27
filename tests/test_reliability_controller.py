"""Verify durable status reconciliation, idempotence, and independent execution boundaries."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from incident_copilot.models import ValidationError
from incident_copilot.reliability_controller import ReconcileConflict, ReliabilityController


ROOT = Path(__file__).resolve().parents[1]


def fixture(name, directory="controller"):
    """Load synthetic API/collector snapshots."""
    return json.loads((ROOT / "examples" / directory / f"{name}.json").read_text(encoding="utf-8"))


class ControllerHarness(unittest.TestCase):
    """Share durable stores, a reviewed replay cohort, and independent receipts."""

    def setUp(self):
        """Register API resource kinds without trusting their input status."""
        # unittest cleanup spans setup, test methods, and store replacement on restart.
        # pylint: disable-next=consider-using-with
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = str(Path(self.directory.name) / "controller.sqlite3")
        self.platform = fixture("platform")
        self.scenario = fixture("success-scenario")
        self.store = ReliabilityController(self.path, self.platform)
        self.addCleanup(self._close_store)
        for resource in self.scenario["resources"]:
            self.store.register(resource)
        self.sources = {"context": fixture("hpa-context", "autonomy"),
                        "capabilityPlatform": fixture("capability-platform", "rollout"),
                        "replay": fixture("replay", "rollout")}

    def frame(self, index, scenario=None):
        """Resolve review sources as the CLI does, preserving exact bindings."""
        result = deepcopy((scenario or self.scenario)["frames"][index])
        if result["event"] == "review":
            result["payload"] = deepcopy(self.sources)
        return result

    def _close_store(self):
        """Close whichever store instance is current after a restart test."""
        self.store.close()

    def replay(self, stop=None, scenario=None):
        """Apply a prefix or complete lifecycle to the persisted core."""
        scenario = scenario or self.scenario
        return [self.store.reconcile(self.frame(index, scenario))
                for index in range(len(scenario["frames"]) if stop is None else stop)]

    def status(self):
        """Inspect controller-owned proposal state."""
        return self.store.resource("proposal-uid")["status"]


class ControllerLifecycleTests(ControllerHarness):
    """Exercise user-facing verification through forward and recovery loops."""

    def test_success_requires_convergence_then_user_sli_verification(self):
        """GitOps convergence cannot itself mark remediation successful."""
        self.replay(9)
        self.assertEqual(self.status()["phase"], "Verifying")
        self.store.reconcile(self.frame(9))
        self.assertEqual(self.status()["phase"], "Succeeded")
        self.assertEqual(self.status()["verification"]["outcome"], "SUCCESS")
        self.assertEqual(self.store.resource("investigation-uid")["status"]["toolCalls"], 3)

    def test_duplicate_delivery_and_restart_do_not_repeat_work(self):
        """State and work IDs survive restart, including terminal replay."""
        receipts = self.replay()
        self.assertTrue(receipts[6]["duplicate"])
        work = self.store.pending_work()
        self.assertEqual(sum(item["kind"] == "request_git_workflow" for item in work), 1)
        self.store.close()
        self.store = ReliabilityController(self.path, self.platform)
        for resource in self.scenario["resources"]:
            self.store.register(resource)
        self.assertTrue(all(receipt["duplicate"] for receipt in self.replay()))
        self.assertEqual(work, self.store.pending_work())

    def test_failure_requires_separate_rollback_review_and_reverification(self):
        """Failed verification does not automatically authorize reversal."""
        scenario = fixture("rollback-scenario")
        self.replay(10, scenario)
        self.assertEqual(self.status()["phase"], "Failed")
        self.assertNotIn("request_reviewed_git_revert", {item["kind"]
                                                        for item in self.store.pending_work()})
        self.store.reconcile(self.frame(10, scenario))
        self.assertEqual(self.status()["phase"], "RollingBack")
        self.store.reconcile(self.frame(11, scenario))
        self.assertEqual(self.status()["phase"], "VerifyingRollback")
        self.store.reconcile(self.frame(12, scenario))
        self.assertEqual(self.status()["phase"], "RolledBack")

    def test_already_desired_git_state_does_not_open_a_second_pr(self):
        """Desired Git with lagging live state requests reconciler diagnosis."""
        self.replay(5)
        frame = self.frame(5)
        frame["payload"]["gitDesired"] = 20
        self.store.reconcile(frame)
        self.assertEqual(self.status()["phase"], "AwaitingConvergence")
        kinds = {item["kind"] for item in self.store.pending_work()}
        self.assertIn("diagnose_reconciliation", kinds)
        self.assertNotIn("request_git_workflow", kinds)

    def test_already_converged_state_is_no_change_not_claimed_recovery(self):
        """No remediation applied means no causal recovery claim."""
        self.replay(5)
        frame = self.frame(5)
        frame["payload"].update(gitDesired=20, liveValue=20)
        self.store.reconcile(frame)
        self.assertEqual(self.status()["phase"], "NoChange")
        self.assertNotIn("request_git_workflow", {
            item["kind"] for item in self.store.pending_work()})

    def test_partial_gitops_rollout_waits_without_a_retry_pr(self):
        """Unconverged receipts cannot skip to success or enqueue another change."""
        self.replay(8)
        frame = self.frame(8)
        frame["payload"]["liveValue"] = 10
        self.assertFalse(self.store.reconcile(frame)["changed"])
        self.assertEqual(self.status()["phase"], "Executing")
        self.assertEqual(sum(item["kind"] == "request_git_workflow"
                             for item in self.store.pending_work()), 1)

    def test_unexpected_critical_signals_freeze_and_escalate(self):
        """Unexpected signals cannot trigger an unreviewed reversal."""
        self.replay(9)
        frame = self.frame(9)
        frame["payload"]["observations"]["new_critical_alert"] = True
        self.store.reconcile(frame)
        self.assertEqual(self.status()["phase"], "Escalated")


class ControllerSafetyTests(ControllerHarness):
    """Check identity, provenance, policy, freshness, and concurrency boundaries."""

    def test_input_status_cannot_self_authorize_and_specs_are_immutable(self):
        """Forged status never overwrites controller-owned state."""
        resource = deepcopy(self.scenario["resources"][2])
        resource["status"] = {"phase": "Authorized", "autonomyLevel": 5}
        self.store.register(resource)
        self.assertEqual(self.status()["phase"], "Proposed")
        resource["spec"]["currentMaxReplicas"] = 11
        with self.assertRaises(ValidationError):
            self.store.register(resource)

    def test_stale_status_revision_cannot_add_work(self):
        """CAS failures require reload without losing or repeating queued work."""
        self.replay(1)
        frame = self.frame(1)
        frame["expectedRevision"] = 0
        before = self.store.pending_work()
        with self.assertRaises(ReconcileConflict):
            self.store.reconcile(frame)
        self.assertEqual(before, self.store.pending_work())

    def test_role_spoofing_changed_receipts_and_out_of_order_events_are_rejected(self):
        """An investigator cannot issue independent policy or production receipts."""
        frame = self.frame(4)
        frame["principal"] = self.platform["principals"]["investigator"]
        with self.assertRaises(ValidationError):
            self.store.reconcile(frame)
        self.replay(1)
        changed = self.frame(0)
        changed["payload"] = {"unexpected": True}
        with self.assertRaises(ValidationError):
            self.store.reconcile(changed)
        out_of_order = self.frame(2)
        out_of_order["expectedRevision"] = 1
        with self.assertRaises(ValidationError):
            self.store.reconcile(out_of_order)

    def test_target_uid_and_live_baseline_substitution_cannot_dispatch(self):
        """Exact UID and fresh-state preconditions precede workflow creation."""
        self.replay(5)
        frame = self.frame(5)
        frame["payload"]["targetUid"] = "hallucinated-target"
        with self.assertRaises(ValidationError):
            self.store.reconcile(frame)
        frame["payload"].update(targetUid="hpa-payments-uid", liveValue=11)
        self.store.reconcile(frame)
        self.assertEqual(self.status()["phase"], "Escalated")
        self.assertNotIn("request_git_workflow", {
            item["kind"] for item in self.store.pending_work()})

    def test_expired_authorization_does_not_dispatch(self):
        """A prior eligibility result cannot bypass approval freshness."""
        self.replay(5)
        frame = self.frame(5)
        frame["at"] = "2026-11-02T12:06:00Z"
        frame["payload"]["observedAt"] = frame["at"]
        self.store.reconcile(frame)
        self.assertEqual(self.status()["phase"], "AwaitingApproval")

    def test_investigation_deadline_stops_collection(self):
        """A delayed reconcile escalates rather than invoking unbounded collectors."""
        frame = self.frame(0)
        frame["at"] = "2026-11-02T12:10:00Z"
        self.store.reconcile(frame)
        self.assertEqual(self.store.resource("investigation-uid")["status"]["phase"], "Escalated")
        self.assertEqual(len(self.store.pending_work()), 1)

    def test_conflicting_proposals_cannot_open_parallel_git_workflows(self):
        """A durable per-target lock extends beyond one proposal's stable work IDs."""
        self.replay(6)
        other = deepcopy(self.scenario["resources"][2])
        other["metadata"].update(name="another-proposal", uid="another-uid")
        self.store.register(other)
        for index in (3, 4, 5):
            frame = self.frame(index)
            frame.update(id=f"other-{index}", uid="another-uid",
                         expectedRevision=self.store.resource("another-uid")["revision"])
            self.store.reconcile(frame)
        self.assertEqual(self.store.resource("another-uid")["status"]["phase"], "Escalated")
        self.assertEqual(sum(item["kind"] == "request_git_workflow"
                             for item in self.store.pending_work()), 1)

    def test_stricter_cr_policy_can_veto_existing_preapproval(self):
        """A Level 5 grant still obeys the specific referenced RemediationPolicy."""
        policy = deepcopy(self.scenario["resources"][1])
        policy["metadata"].update(name="strict-policy", uid="strict-policy-uid")
        policy["spec"]["maximumIncrease"] = 1.5
        self.store.register(policy)
        proposal = deepcopy(self.scenario["resources"][2])
        proposal["metadata"].update(name="strict-proposal", uid="strict-proposal-uid")
        proposal["spec"]["policyRef"].update(name="strict-policy", uid="strict-policy-uid")
        self.store.register(proposal)
        self.replay(3)
        for index in (3, 4):
            frame = self.frame(index)
            frame.update(uid="strict-proposal-uid", id=f"strict-{index}",
                         expectedRevision=self.store.resource("strict-proposal-uid")["revision"])
            self.store.reconcile(frame)
        self.assertEqual(self.store.resource("strict-proposal-uid")["status"]["phase"], "Denied")

    def test_manual_only_cr_policy_cannot_relabel_an_automatic_grant(self):
        """A Level 4 ceiling still requires an actual independent manual receipt."""
        policy = deepcopy(self.scenario["resources"][1])
        policy["metadata"].update(name="manual-policy", uid="manual-policy-uid")
        policy["spec"]["maximumAutonomyLevel"] = 4
        self.store.register(policy)
        proposal = deepcopy(self.scenario["resources"][2])
        proposal["metadata"].update(name="manual-proposal", uid="manual-proposal-uid")
        proposal["spec"]["policyRef"].update(name="manual-policy", uid="manual-policy-uid")
        self.store.register(proposal)
        self.replay(3)
        for index in (3, 4):
            frame = self.frame(index)
            frame.update(uid="manual-proposal-uid", id=f"manual-{index}",
                         expectedRevision=self.store.resource("manual-proposal-uid")["revision"])
            self.store.reconcile(frame)
        status = self.store.resource("manual-proposal-uid")["status"]
        self.assertEqual(status["phase"], "AwaitingApproval")
        self.assertEqual(status["autonomyLevel"], 3)


class ControllerArtifactTests(unittest.TestCase):
    """Check packaged schemas, RBAC scope, and the actual replay CLI."""

    def test_crds_have_immutable_specs_and_status_only_write_permissions(self):
        """No reference role can patch HPAs or create its own RemediationPolicy."""
        for name in ("investigations", "remediationproposals", "remediationpolicies"):
            crd = json.loads((ROOT / "deploy" / "reliability" / f"{name}.json").read_text())
            version = crd["spec"]["versions"][0]
            self.assertEqual(version["subresources"], {"status": {}})
            self.assertEqual(crd["spec"]["scope"], "Namespaced")
            schema = version["schema"]["openAPIV3Schema"]["properties"]["spec"]
            self.assertEqual(schema["x-kubernetes-validations"][0]["rule"], "self == oldSelf")
        role = json.loads((ROOT / "deploy" / "reliability" / "role.json").read_text())
        writable = {resource for rule in role["rules"] if set(rule["verbs"]) & {"update", "patch"}
                    for resource in rule["resources"]}
        self.assertEqual(writable, {"investigations/status", "remediationproposals/status"})

    def test_cli_resume_preserves_exactly_one_git_request(self):
        """The published command resumes all durable receipts and work after restart."""
        with tempfile.TemporaryDirectory() as directory:
            args = [sys.executable, "-m", "incident_copilot.controller_cli", "--platform",
                    "examples/controller/platform.json", "--scenario",
                    "examples/controller/success-scenario.json", "--review-context",
                    "examples/autonomy/hpa-context.json", "--capability-platform",
                    "examples/rollout/capability-platform.json", "--replay",
                    "examples/rollout/replay.json", "--state", str(Path(directory) / "state.db")]
            for _ in range(2):
                result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(sum(item["kind"] == "request_git_workflow"
                                     for item in report["pending_work"]), 1)
