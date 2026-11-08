"""Exercise durable event processing, investigation bounds, and independent approvals."""

import base64
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from incident_copilot.event_orchestrator import EventOrchestrator
from incident_copilot.events import decode_pubsub_push, validate_context, validate_event
from incident_copilot.models import ValidationError


EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "events"


def fixture(name):
    """Read fresh synthetic contracts for each test."""
    return json.loads((EXAMPLES / f"{name}.json").read_text(encoding="utf-8"))


class EventHarness(unittest.TestCase):
    """Share an isolated worker and fixture helpers across lifecycle and safety tests."""

    def setUp(self):
        """Give each test an isolated local worker and independent producer identities."""
        self.context = fixture("context")
        self.deliveries = fixture("checkout-deliveries")
        self.store = EventOrchestrator(":memory:", self.context)
        self.addCleanup(self.store.close)

    def deliver(self, delivery):
        """Use adapter-supplied identity and time, independently of the event source string."""
        return self.store.process(delivery["event"], delivery["principal"], delivery["received_at"])

    def replay(self, stop=None):
        """Advance a known lifecycle up to an exclusive fixture index."""
        for delivery in self.deliveries[:stop]:
            self.deliver(delivery)

    def state(self):
        """Read a fresh copy of the incident record."""
        return self.store.incident("INC-3921")

    def outputs(self, kind):
        """Select queued work without marking any network publication."""
        return [event for event in self.store.pending_outbox() if event["type"] == kind]


class EventTests(EventHarness):
    """Validate replay and crash behavior without brokers, models, or cloud credentials."""

    def test_complete_progressive_investigation_and_late_slo_verification(self):
        """Five bounded reads, three model rounds, and independent attestations resolve the case."""
        self.replay()
        self.assertEqual(self.state()["phase"], "resolved")
        self.assertEqual(self.state()["tool_calls"], 5)
        self.assertEqual(len(self.outputs("investigation.requested")), 3)
        execution = self.outputs("remediation.execution_requested")[0]["payload"]
        self.assertEqual(execution["controller"], "terraform")
        self.assertEqual(execution["git_path"], "infra/production/pricing-db.tf")
        self.assertEqual(execution["execution_path"], "reviewed_gitops_only")
        for event in self.store.pending_outbox():
            for key in ("incident_id", "trace_id", "agent_version"):
                self.assertEqual(event[key], self.deliveries[0]["event"][key])

    def test_three_initial_collectors_must_finish_before_reasoning(self):
        """Partial initial context never queues the investigator."""
        self.replay(3)
        self.assertEqual(len(self.outputs("evidence.collection_requested")), 3)
        self.assertFalse(self.outputs("investigation.requested"))
        self.deliver(self.deliveries[3])
        self.assertEqual(len(self.outputs("incident.context_ready")), 1)
        self.assertEqual(len(self.outputs("investigation.requested")), 1)

    def test_replays_after_restart_do_not_repeat_work_and_publish_receipts_persist(self):
        """Inbox and outbox changes survive reopening the local database."""
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "state.sqlite3")
            store = EventOrchestrator(path, self.context)
            delivery = self.deliveries[0]
            store.process(delivery["event"], delivery["principal"], delivery["received_at"])
            first = store.pending_outbox()[0]["event_id"]
            store.mark_published(first)
            store.close()
            store = EventOrchestrator(path, self.context)
            try:
                receipt = store.process(delivery["event"], delivery["principal"],
                                        delivery["received_at"])
                self.assertEqual(receipt["decision"], "duplicate")
                self.assertEqual(len(store.pending_outbox()), 2)
                self.assertEqual(store.incident("INC-3921")["tool_calls"], 3)
            finally:
                store.close()
            changed = deepcopy(self.context)
            changed["agent_version"] = "different-agent"
            with self.assertRaises(ValidationError):
                EventOrchestrator(path, changed)

    def test_event_id_reuse_with_changed_content_is_rejected(self):
        """A transport duplicate cannot silently replace its original trigger."""
        self.replay(1)
        changed = deepcopy(self.deliveries[0])
        changed["event"]["payload"]["value"] = 0.25
        with self.assertRaises(ValidationError):
            self.deliver(changed)
        self.assertEqual(len(self.store.pending_outbox()), 3)

    def test_semantic_duplicate_trigger_does_not_refan_out(self):
        """The incident key protects against a normalizer issuing a second event ID."""
        self.replay(1)
        changed = deepcopy(self.deliveries[0])
        changed["event"]["event_id"] = "new-trigger-id"
        self.deliver(changed)
        self.assertEqual(len(self.store.pending_outbox()), 3)

    def test_unauthorized_principal_changed_trace_and_agent_are_rejected(self):
        """A source label never grants approval or another incident's correlation."""
        self.replay(1)
        for key, value in (("trace_id", "a" * 32), ("agent_version", "other-version")):
            changed = deepcopy(self.deliveries[1])
            changed["event"][key] = value
            with self.subTest(key=key), self.assertRaises(ValidationError):
                self.deliver(changed)
        self.replay(1)
        changed = deepcopy(self.deliveries[12])
        changed["principal"] = self.context["principals"]["investigator"]
        with self.assertRaises(ValidationError):
            self.deliver(changed)

    def test_out_of_order_delivery_recovers_after_initial_trigger(self):
        """Do not acknowledge an early message or count deliveries before its backoff expires."""
        early = deepcopy(self.deliveries[1])
        receipt = self.deliver(early)
        self.assertFalse(receipt["ack"])
        self.assertEqual(receipt["next_at"], "2026-11-07T12:00:15+00:00")
        self.deliver(early)
        self.assertEqual(self.store.audit()[0]["attempts"], 1)
        self.deliver(self.deliveries[0])
        early["received_at"] = receipt["next_at"]
        self.assertTrue(self.deliver(early)["ack"])
        self.assertTrue(self.state()["requests"]["e00-kubernetes"]["complete"])

    def test_out_of_order_exhaustion_queues_one_dead_letter_and_notification(self):
        """Three durable application attempts terminate a missing lifecycle dependency."""
        early = deepcopy(self.deliveries[1])
        for now in ("12:00:10Z", "12:00:15Z", "12:00:25Z"):
            early["received_at"] = f"2026-11-07T{now}"
            receipt = self.deliver(early)
        self.assertEqual(receipt["decision"], "dead_letter")
        self.assertTrue(receipt["ack"])
        self.assertEqual(self.deliver(early)["decision"], "duplicate")
        self.assertEqual(len(self.outputs("incident.dead_lettered")), 1)
        self.assertEqual(len(self.outputs("incident.notification_requested")), 1)

    def test_reasoning_timeouts_have_bounded_attempts_and_scheduled_backoff(self):
        """Timeout handling requests notification through the independent incident route."""
        for delivery in fixture("timeout-deliveries"):
            self.deliver(delivery)
        jobs = self.outputs("investigation.requested")
        self.assertEqual([job["payload"]["attempt"] for job in jobs], [1, 2, 3])
        self.assertEqual(jobs[1]["payload"]["next_at"], "2026-11-07T12:00:36+00:00")
        self.assertEqual(jobs[2]["payload"]["next_at"], "2026-11-07T12:00:46+00:00")
        self.assertEqual(self.state()["phase"], "escalated")
        self.assertEqual(len(self.outputs("incident.dead_lettered")), 1)
        self.assertEqual(len(self.outputs("incident.notification_requested")), 1)

    def test_stale_reasoning_results_cannot_complete_a_new_attempt(self):
        """A result arriving after a recorded timeout belongs to a closed attempt."""
        for delivery in fixture("timeout-deliveries")[:5]:
            self.deliver(delivery)
        with self.assertRaises(ValidationError):
            self.deliver(self.deliveries[4])
        self.assertEqual(self.state()["reasoning"]["attempt"], 2)

    def test_transaction_rolls_back_state_inbox_and_outbox_on_failure(self):
        """A crash after writing work cannot acknowledge or persist a partial fanout."""
        original = self.store._emit  # pylint: disable=protected-access

        def crash(*args, **kwargs):
            original(*args, **kwargs)
            raise sqlite3.OperationalError("simulated disk failure")

        with patch.object(self.store, "_emit", side_effect=crash):
            with self.assertRaises(sqlite3.OperationalError):
                self.deliver(self.deliveries[0])
        self.assertIsNone(self.state())
        self.assertFalse(self.store.audit())
        self.assertFalse(self.store.pending_outbox())
        self.deliver(self.deliveries[0])
        self.assertEqual(len(self.store.pending_outbox()), 3)

    def test_tool_whitelist_and_resource_scope_reject_shell_and_wrong_targets(self):
        """Typed reads cannot become a shell command or reach another database."""
        self.replay(5)
        for key, value in (("tool", "gcloud_sql_patch"), ("target", "unknown-database")):
            delivery = deepcopy(self.deliveries[5])
            delivery["event"]["payload"][key] = value
            with self.subTest(key=key), self.assertRaises(ValidationError):
                self.deliver(delivery)
        self.assertEqual(self.state()["tool_calls"], 3)

    def test_tool_budget_exhaustion_escalates_without_queuing_an_extra_tool(self):
        """The platform enforces its own limit before calling a tool."""
        context = deepcopy(self.context)
        context["limits"]["max_tool_calls"] = 3
        store = EventOrchestrator(":memory:", context)
        self.addCleanup(store.close)
        for delivery in self.deliveries[:6]:
            store.process(delivery["event"], delivery["principal"], delivery["received_at"])
        self.assertEqual(store.incident("INC-3921")["phase"], "escalated")
        reads = [event for event in store.pending_outbox()
                 if event["type"] == "evidence.collection_requested"]
        self.assertEqual(len(reads), 3)

    def test_sweep_detects_silent_collectors_and_does_not_repeat_escalation(self):
        """Budget expiry also works when no evidence or timeout event ever arrives."""
        self.replay(1)
        self.assertFalse(self.store.expire("2026-11-07T12:05:00Z"))
        self.assertEqual(self.store.expire("2026-11-07T12:05:01Z"), ["INC-3921"])
        self.assertFalse(self.store.expire("2026-11-07T12:06:00Z"))
        self.assertEqual(len(self.outputs("incident.notification_requested")), 1)
        with self.assertRaises(ValidationError):
            self.deliver(self.deliveries[1])

    def test_nonbreaching_and_stale_triggers_do_not_queue_collectors(self):
        """False alarms and exhausted budgets never invoke reasoning."""
        delivery = deepcopy(self.deliveries[0])
        delivery["event"]["payload"]["value"] = 0.01
        self.deliver(delivery)
        self.assertEqual(self.state()["phase"], "no_action")
        self.assertFalse(self.outputs("evidence.collection_requested"))
        delivery = deepcopy(self.deliveries[0])
        delivery["event"]["incident_id"] = "stale-incident"
        delivery["event"]["event_id"] = "stale-trigger"
        delivery["received_at"] = "2026-11-07T12:06:00Z"
        self.deliver(delivery)
        self.assertEqual(self.store.incident("stale-incident")["phase"], "escalated")
        self.assertFalse(self.outputs("evidence.collection_requested"))


class EventSafetyTests(EventHarness):
    """Preserve provenance, declarative ownership, and independent authority boundaries."""

    def test_proposal_requires_confidence_falsification_and_collected_evidence(self):
        """Model assertions do not replace even the lifecycle's minimum investigation checks."""
        for invalid in ("confidence", "falsification", "evidence"):
            with self.subTest(invalid=invalid):
                deliveries = deepcopy(self.deliveries[:12])
                if invalid == "confidence":
                    for hypothesis, weight in zip(
                            deliveries[10]["event"]["payload"]["hypotheses"], [.02, .06, .90, .02]):
                        hypothesis["confidence"] = weight
                elif invalid == "falsification":
                    deliveries[10]["event"]["payload"]["falsification_completed"] = False
                else:
                    deliveries[11]["event"]["payload"]["evidence_ids"] = ["unknown", "x", "y"]
                store = EventOrchestrator(":memory:", self.context)
                try:
                    for delivery in deliveries[:-1]:
                        store.process(delivery["event"], delivery["principal"],
                                      delivery["received_at"])
                    delivery = deliveries[-1]
                    with self.assertRaises(ValidationError):
                        store.process(delivery["event"], delivery["principal"],
                                      delivery["received_at"])
                    self.assertEqual(store.incident("INC-3921")["phase"], "investigating")
                finally:
                    store.close()

    def test_mismatched_approval_artifacts_never_queue_execution(self):
        """The approval principal cannot substitute a different plan, intent, or SLO contract."""
        self.replay(12)
        for field in ("intent_sha256", "plan_sha256", "verification_sha256", "proposal_event_id"):
            changed = deepcopy(self.deliveries[12])
            changed["event"]["payload"][field] = "b" * 64
            with self.subTest(field=field), self.assertRaises(ValidationError):
                self.deliver(changed)
        self.assertFalse(self.outputs("remediation.execution_requested"))
        self.assertEqual(self.state()["phase"], "proposed")

    def test_execution_before_approval_waits_without_work(self):
        """Out-of-order controller attestations cannot bypass independent approval."""
        self.replay(12)
        self.assertFalse(self.deliver(self.deliveries[13])["ack"])
        self.assertEqual(self.state()["phase"], "proposed")
        self.assertFalse(self.outputs("remediation.verification_requested"))

    def test_changed_verification_revision_and_contract_are_rejected(self):
        """SLO success must describe the approved revision and original verification contract."""
        self.replay(14)
        for field, value in (("revision", "b" * 40), ("verification_sha256", "b" * 64)):
            changed = deepcopy(self.deliveries[14])
            changed["event"]["payload"][field] = value
            with self.subTest(field=field), self.assertRaises(ValidationError):
                self.deliver(changed)
        self.assertEqual(self.state()["phase"], "executed")

    def test_failed_verification_requests_reviewed_revert_and_human_notification(self):
        """Failure emits requests for external action and never applies a rollback."""
        self.replay(14)
        delivery = deepcopy(self.deliveries[14])
        delivery["event"]["payload"]["outcome"] = "FAILED"
        self.deliver(delivery)
        self.assertEqual(self.state()["phase"], "verification_failed")
        self.assertEqual(len(self.outputs("incident.notification_requested")), 1)
        revert = self.outputs("remediation.revert_review_requested")[0]
        self.assertTrue(revert["payload"]["requires_independent_policy_and_approval"])

    def test_inconclusive_verification_escalates_without_revert(self):
        """Missing proof of recovery calls for investigation, not an assumed failed deployment."""
        self.replay(14)
        delivery = deepcopy(self.deliveries[14])
        delivery["event"]["payload"]["outcome"] = "INCONCLUSIVE"
        self.deliver(delivery)
        self.assertEqual(self.state()["phase"], "escalated")
        self.assertFalse(self.outputs("remediation.revert_review_requested"))

    def test_late_investigator_event_cannot_overwrite_an_approved_change(self):
        """A delayed duplicate with a new ID cannot expire a completed investigation."""
        self.replay(13)
        delivery = deepcopy(self.deliveries[10])
        delivery["event"]["event_id"] = "late-result"
        delivery["received_at"] = "2026-11-07T12:10:00Z"
        with self.assertRaises(ValidationError):
            self.deliver(delivery)
        self.assertFalse(self.store.expire(delivery["received_at"]))
        self.assertEqual(self.state()["phase"], "approved")

    def test_invalid_payload_types_and_authority_configuration_fail_closed(self):
        """Malformed enums, unbounded input, and shared authority identities are invalid."""
        for value in ([], {}, True):
            delivery = deepcopy(self.deliveries[0])
            delivery["event"]["payload"]["signal"] = value
            with self.subTest(value=value), self.assertRaises(ValidationError):
                self.deliver(delivery)
        self.context["principals"]["approval-service"] = self.context["principals"]["investigator"]
        with self.assertRaises(ValidationError):
            validate_context(self.context)

    def test_wrapped_pubsub_decoder_is_bounded_and_never_supplies_identity(self):
        """Decoding the data field grants no trust to message attributes or source claims."""
        event = self.deliveries[0]["event"]
        envelope = {"message": {"data": base64.b64encode(json.dumps(event).encode()).decode(),
                                 "attributes": {"principal": "monitoring"}}}
        decoded = decode_pubsub_push(envelope)
        self.assertEqual(decoded, event)
        with self.assertRaises(ValidationError):
            validate_event(decoded, self.context, "monitoring", self.deliveries[0]["received_at"])
        with self.assertRaises(ValidationError):
            decode_pubsub_push(envelope, max_bytes=10)
        for data in ("invalid!", "//4=", "e30="):
            envelope["message"]["data"] = data
            if data == "e30=":
                self.assertEqual(decode_pubsub_push(envelope), {})
            else:
                with self.assertRaises(ValidationError):
                    decode_pubsub_push(envelope)

    def test_cli_success_timeout_and_invalid_input_exit_codes(self):
        """Packaged replay commands expose reviewable success, escalation, and malformed input."""
        command = [sys.executable, "-m", "incident_copilot.events_cli",
                   "--context", str(EXAMPLES / "context.json"), "--deliveries",
                   str(EXAMPLES / "checkout-deliveries.json"), "--state", ":memory:"]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["incidents"][0]["phase"], "resolved")
        command[command.index("--deliveries") + 1] = str(EXAMPLES / "timeout-deliveries.json")
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1, result.stderr)
        command[command.index("--deliveries") + 1] = str(EXAMPLES / "context.json")
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
