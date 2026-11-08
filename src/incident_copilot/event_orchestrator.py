"""Durable local incident state machine with inbox deduplication and a transactional outbox.

All work is emitted as correlated events. No collector, LLM, production mutation,
approval, PR, or notification is executed inside the database transaction.
"""

from datetime import timedelta
from copy import deepcopy
import json
import sqlite3

from .events import timestamp, validate_context, validate_event
from .models import ValidationError
from .rollout import fingerprint


INITIAL_COLLECTORS = ("kubernetes", "telemetry", "changes")
INVESTIGATION_EVENTS = {"evidence.requested", "evidence.collected", "hypothesis.updated",
                        "investigation.failed", "remediation.proposed"}


class OutOfOrder(Exception):
    """A valid message is waiting for an earlier lifecycle event."""


class EventOrchestrator:
    """One durable local worker; production needs authenticated adapters and shared storage."""

    def __init__(self, path, context):
        validate_context(context)
        self.context = deepcopy(context)
        self.db = sqlite3.connect(path, isolation_level=None, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY, context_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS inbox (
                id TEXT PRIMARY KEY, digest TEXT NOT NULL, body TEXT NOT NULL,
                status TEXT NOT NULL, attempts INTEGER NOT NULL, next_at TEXT);
            CREATE TABLE IF NOT EXISTS outbox (
                id TEXT PRIMARY KEY, body TEXT NOT NULL, published INTEGER NOT NULL DEFAULT 0);
        """)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute("INSERT OR IGNORE INTO metadata VALUES (1, ?)", (fingerprint(context),))
            stored_hash = self.db.execute(
                "SELECT context_hash FROM metadata WHERE id=1").fetchone()[0]
            matches = stored_hash == fingerprint(context)
        if not matches:
            self.db.close()
            raise ValidationError("state database belongs to a different agent configuration")

    def close(self):
        """Release the local store after a replay or adapter operation."""
        self.db.close()

    def process(self, event, principal, received_at):
        """Commit state, deduplication, and output together before returning an ack decision."""
        event_hash = validate_event(event, self.context, principal, received_at)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute("SELECT * FROM inbox WHERE id=?", (event["event_id"],)).fetchone()
            if row and row["digest"] != event_hash:
                raise ValidationError("event id was reused with different content")
            if row and row["status"] != "retry":
                return {"decision": "duplicate", "ack": True, "event_id": event["event_id"]}
            if row and timestamp(received_at) < timestamp(row["next_at"]):
                return {"decision": "retry", "ack": False, "next_at": row["next_at"]}
            state = self.incident(event["incident_id"])
            self._identity(state, event)
            attempts = row["attempts"] + 1 if row else 1
            receipt = self._apply_with_retry(state, event, attempts, received_at)
            self.db.execute(
                "INSERT OR REPLACE INTO inbox VALUES (?, ?, ?, ?, ?, ?)",
                (event["event_id"], event_hash, json.dumps(event), receipt["decision"],
                 attempts, receipt.get("next_at")),
            )
            return receipt

    def _identity(self, state, event):
        """Pin every continuation to the incident's original trace and investigator version."""
        if state and any(state[key] != event[key] for key in ("trace_id", "agent_version")):
            raise ValidationError("incident correlation or agent version changed")

    def _apply_with_retry(self, state, event, attempts, now):
        """Bound out-of-order delivery without acknowledging an uncommitted state change."""
        try:
            updated = self._apply(state, event, now)
        except OutOfOrder:
            if attempts < self.context["limits"]["max_delivery_attempts"]:
                return {"decision": "retry", "ack": False,
                        "next_at": self._retry_at(now, attempts)}
            self._emit(event, "incident.dead_lettered", {
                "failed_event_id": event["event_id"], "event_sha256": fingerprint(event),
                "reason": "out_of_order", "attempts": attempts,
            }, now)
            updated = self._escalate(state, event, "delivery_attempts_exhausted", now)
            decision = "dead_letter"
        else:
            decision = "accepted"
        if updated is not None:
            self.db.execute("INSERT OR REPLACE INTO incidents VALUES (?, ?)",
                            (event["incident_id"], json.dumps(updated)))
        return {"decision": decision, "ack": True, "event_id": event["event_id"],
                "state": updated["phase"] if updated else None}

    def _retry_at(self, now, attempts):
        """Return deterministic bounded exponential backoff; never sleep inside the worker."""
        delay = min(300, self.context["limits"]["retry_base_seconds"] * 2 ** (attempts - 1))
        return (timestamp(now) + timedelta(seconds=delay)).isoformat()

    def _emit(self, parent, kind, payload, now, key=""):
        """Write a stable, fully correlated outbox event in the current transaction."""
        event_id = fingerprint({"parent": parent["event_id"], "kind": kind, "key": key})[:32]
        event = {"event_id": event_id, "type": kind, "incident_id": parent["incident_id"],
                 "trace_id": parent["trace_id"], "agent_version": parent["agent_version"],
                 "timestamp": now, "source": "orchestrator", "payload": payload}
        self.db.execute("INSERT INTO outbox (id, body) VALUES (?, ?)",
                        (event_id, json.dumps(event)))

    def _escalate(self, state, event, reason, now):
        """Request independent human notification; do not alter the monitoring system."""
        if state:
            state["phase"] = "escalated"
            state["escalation_reason"] = reason
        self._emit(event, "incident.notification_requested", {"reason": reason,
                   "route": "traditional_incident_response", "action": "escalate"}, now)
        return state

    def _apply(self, state, event, now):
        """Dispatch a typed lifecycle event after checking identity and time budget."""
        if event["type"] == "incident.created":
            return self._created(state, event, now)
        if state is None:
            raise OutOfOrder()
        if state["phase"] in {"resolved", "verification_failed", "escalated", "no_action"}:
            raise ValidationError("incident is terminal; open a new incident to investigate")
        if event["type"] in INVESTIGATION_EVENTS and state["phase"] in {
                "proposed", "approved", "executed"}:
            raise ValidationError("investigation is closed after proposal; review a new incident")
        if event["type"] in INVESTIGATION_EVENTS and (
                timestamp(now) > timestamp(state["deadline"])):
            return self._escalate(state, event, "investigation_time_budget_exhausted", now)
        handlers = {
            "evidence.requested": self._requested, "evidence.collected": self._collected,
            "hypothesis.updated": self._hypothesis, "investigation.failed": self._failed,
            "remediation.proposed": self._proposed, "remediation.approved": self._approved,
            "remediation.executed": self._executed, "remediation.verified": self._verified,
        }
        handlers[event["type"]](state, event, now)
        return state

    def _created(self, state, event, now):
        """Start exactly three deterministic collectors before requesting any reasoning."""
        payload = event["payload"]
        if (payload["service"] not in self.context["services"]
                or payload["environment"] != self.context["environment"]):
            raise ValidationError("incident target is outside platform scope")
        if timestamp(payload["started_at"]) > timestamp(event["timestamp"]):
            raise ValidationError("incident start is after notification")
        if state:
            if state["trigger_sha256"] != fingerprint(payload):
                raise ValidationError("incident id was reused for another alert")
            return state
        state = {"incident_id": event["incident_id"], "trace_id": event["trace_id"],
                 "agent_version": event["agent_version"], "service": payload["service"],
                 "environment": payload["environment"], "trigger_sha256": fingerprint(payload),
                 "deadline": (timestamp(payload["started_at"]) + timedelta(
                     seconds=self.context["limits"]["max_investigation_seconds"])).isoformat(),
                 "phase": "collecting", "requests": {}, "evidence": {},
                 "tool_calls": 0, "hypotheses": [], "reasoning": None}
        if payload["value"] <= payload["threshold"]:
            state["phase"] = "no_action"
            self._emit(event, "incident.no_action", {"reason": "signal_not_breaching"}, now)
            return state
        if timestamp(now) > timestamp(state["deadline"]):
            return self._escalate(state, event, "investigation_time_budget_exhausted", now)
        for collector in INITIAL_COLLECTORS:
            request_id = f"{event['event_id']}-{collector}"
            state["requests"][request_id] = {"kind": "initial", "collector": collector,
                                             "complete": False}
            self._emit(event, "evidence.collection_requested", {
                "request_id": request_id, "collector": collector, "service": state["service"],
                "environment": state["environment"], "read_only": True,
            }, now, collector)
            state["tool_calls"] += 1
        return state

    def _requested(self, state, event, now):
        """Authorize a targeted read and count it before any platform tool is invoked."""
        if state["phase"] not in {"investigating", "collecting"} or not state["hypotheses"]:
            raise OutOfOrder()
        payload = event["payload"]
        if payload["request_id"] in state["requests"]:
            raise ValidationError("request id is already in use")
        allowed = self.context["resources"] if payload["tool"] == "get_cloudsql_health" else (
            self.context["services"])
        if payload["target"] not in allowed:
            raise ValidationError("requested evidence target is outside platform scope")
        if state["tool_calls"] >= self.context["limits"]["max_tool_calls"]:
            self._escalate(state, event, "tool_call_budget_exhausted", now)
            return
        state["requests"][payload["request_id"]] = {"kind": "targeted", "complete": False}
        state["tool_calls"] += 1
        state["phase"] = "collecting"
        self._emit(event, "evidence.collection_requested", {
            **payload, "environment": state["environment"], "read_only": True,
        }, now)

    def _collected(self, state, event, now):
        """Keep immutable references while raw telemetry stays in the context store."""
        payload = event["payload"]
        if state["phase"] != "collecting" or payload["request_id"] not in state["requests"]:
            raise OutOfOrder()
        request = state["requests"][payload["request_id"]]
        if request["complete"] or not payload["evidence_ids"]:
            raise ValidationError("evidence request is complete or evidence is empty")
        if set(payload["evidence_ids"]) & set(state["evidence"]):
            raise ValidationError("evidence ids must identify distinct collected facts")
        request["complete"] = True
        for evidence_id in payload["evidence_ids"]:
            state["evidence"][evidence_id] = {"ref": payload["evidence_ref"],
                                               "sha256": payload["evidence_sha256"]}
        if all(request["complete"] for request in state["requests"].values()):
            if not state["hypotheses"]:
                self._emit(event, "incident.context_ready", {"evidence": state["evidence"]}, now)
            self._reasoning(state, event, now)

    def _reasoning(self, state, event, now):
        """Queue a replaceable investigator only after the deterministic context is ready."""
        request_id = f"reason-{event['event_id']}"
        state["reasoning"] = {"request_id": request_id, "attempt": 1, "next_at": now}
        state["phase"] = "reasoning"
        self._emit(event, "investigation.requested", {
            **state["reasoning"], "evidence": state["evidence"], "deadline": state["deadline"],
            "remaining_tool_calls": self.context["limits"]["max_tool_calls"] - state["tool_calls"],
        }, now)

    def _reasoning_match(self, state, payload, now):
        """Reject results from an earlier timed-out attempt or an unrelated work request."""
        if state["phase"] != "reasoning" or state["reasoning"] is None:
            raise OutOfOrder()
        active = state["reasoning"]
        if any(payload[key] != active[key] for key in ("request_id", "attempt")):
            raise ValidationError("reasoning request or attempt does not match active work")
        if timestamp(now) < timestamp(active["next_at"]):
            raise OutOfOrder()

    def _hypothesis(self, state, event, now):
        """Record decision provenance without storing hidden reasoning or executing a suggestion."""
        payload = event["payload"]
        self._reasoning_match(state, payload, now)
        if not set(payload["evidence_ids"]).issubset(state["evidence"]):
            raise ValidationError("hypothesis cites uncollected evidence")
        state["hypotheses"] = payload["hypotheses"]
        state["decision_evidence"] = payload["evidence_ids"]
        state["falsification_completed"] = payload["falsification_completed"]
        state["phase"] = "investigating"

    def _failed(self, state, event, now):
        """Bound reasoning retries independently of Pub/Sub transport delivery attempts."""
        payload = event["payload"]
        self._reasoning_match(state, payload, now)
        active = state["reasoning"]
        if active["attempt"] >= self.context["limits"]["max_reasoning_attempts"]:
            self._emit(event, "incident.dead_lettered", {
                "request_id": active["request_id"], "attempts": active["attempt"],
                "reason": payload["reason"],
            }, now)
            self._escalate(state, event, "reasoning_attempts_exhausted", now)
            return
        active["next_at"] = self._retry_at(now, active["attempt"])
        active["attempt"] += 1
        self._emit(event, "investigation.requested", {
            **active, "evidence": state["evidence"], "deadline": state["deadline"],
            "remaining_tool_calls": self.context["limits"]["max_tool_calls"] - state["tool_calls"],
        }, now)

    def _proposed(self, state, event, now):
        """Route a supported proposal to policy and the owning declarative controller."""
        if state["phase"] != "investigating":
            raise OutOfOrder()
        payload = event["payload"]
        leader = max(state["hypotheses"], key=lambda item: item["confidence"])
        if (payload["hypothesis_id"] != leader["id"] or leader["confidence"] <= 0.90
                or not state["falsification_completed"]
                or len(set(payload["evidence_ids"])) < 3
                or not set(payload["evidence_ids"]).issubset(state["decision_evidence"])):
            raise ValidationError("proposal lacks sufficient reviewed investigation evidence")
        if payload["resource"] not in self.context["resources"]:
            raise ValidationError("proposal resource is outside authoritative catalog")
        state["proposal"] = {**payload, "proposal_event_id": event["event_id"]}
        state["phase"] = "proposed"
        self._emit(event, "remediation.review_requested", {
            **state["proposal"], **self.context["resources"][payload["resource"]],
            "requires_independent_policy_and_approval": True,
        }, now)

    def _approved(self, state, event, now):
        """Require independent approval of the exact intent, plan, and SLO contract."""
        if state["phase"] != "proposed":
            raise OutOfOrder()
        payload = event["payload"]
        self._matches(payload, state["proposal"], (
            "proposal_event_id", "intent_sha256", "plan_sha256", "verification_sha256"))
        state["approval_id"] = payload["approval_id"]
        state["phase"] = "approved"
        self._emit(event, "remediation.execution_requested", {
            **state["proposal"], "approval_id": state["approval_id"],
            **self.context["resources"][state["proposal"]["resource"]],
            "execution_path": "reviewed_gitops_only",
        }, now)

    @staticmethod
    def _matches(payload, expected, keys):
        """Fail closed when a later stage changes a reviewed identity or artifact."""
        if any(payload[key] != expected[key] for key in keys):
            raise ValidationError("lifecycle event differs from reviewed proposal or execution")

    def _executed(self, state, event, now):
        """Record a controller's execution attestation, never run the change."""
        if state["phase"] != "approved":
            raise OutOfOrder()
        payload = event["payload"]
        self._matches(payload, {**state["proposal"], "approval_id": state["approval_id"]},
                      ("proposal_event_id", "approval_id", "plan_sha256"))
        state["revision"] = payload["revision"]
        state["phase"] = "executed"
        self._emit(event, "remediation.verification_requested", {
            "revision": state["revision"],
            "proposal_event_id": state["proposal"]["proposal_event_id"],
            "verification_sha256": state["proposal"]["verification_sha256"],
        }, now)

    def _verified(self, state, event, now):
        """Persist SLO outcome and request evaluation, escalation, or reviewed revert."""
        if state["phase"] != "executed":
            raise OutOfOrder()
        payload = event["payload"]
        self._matches(payload, {**state["proposal"], "revision": state["revision"]},
                      ("proposal_event_id", "revision", "verification_sha256"))
        state["verification"] = payload
        state["phase"] = {"SUCCESS": "resolved", "FAILED": "verification_failed",
                           "INCONCLUSIVE": "escalated"}[payload["outcome"]]
        self._emit(event, "incident.evaluation_requested", {
            "report_ref": payload["report_ref"], "report_sha256": payload["report_sha256"],
            "outcome": payload["outcome"],
        }, now)
        if payload["outcome"] != "SUCCESS":
            self._emit(event, "incident.notification_requested", {
                "reason": "verification_not_successful", "route": "traditional_incident_response",
            }, now)
        if payload["outcome"] == "FAILED":
            self._emit(event, "remediation.revert_review_requested", {
                "revision": state["revision"], "intent_ref": state["proposal"]["intent_ref"],
                "requires_independent_policy_and_approval": True,
            }, now)

    def incident(self, incident_id):
        """Read persisted state; callers cannot mutate it without a subsequent committed event."""
        row = self.db.execute("SELECT body FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def expire(self, now):
        """Sweep silent investigations; an external scheduler supplies the trusted clock."""
        timestamp(now)
        expired = []
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            for row in self.db.execute("SELECT body FROM incidents").fetchall():
                state = json.loads(row[0])
                if state["phase"] not in {"collecting", "reasoning", "investigating"}:
                    continue
                if timestamp(now) <= timestamp(state["deadline"]):
                    continue
                trigger = {**state, "event_id": f"expiry-{state['incident_id']}"}
                self._escalate(state, trigger, "investigation_time_budget_exhausted", now)
                self.db.execute("UPDATE incidents SET body=? WHERE id=?",
                                (json.dumps(state), state["incident_id"]))
                expired.append(state["incident_id"])
        return expired

    def pending_outbox(self):
        """Read committed output for an at-least-once relay; no network publish occurs here."""
        return [json.loads(row[0]) for row in self.db.execute(
            "SELECT body FROM outbox WHERE published=0 ORDER BY rowid")]

    def mark_published(self, event_id):
        """Record relay confirmation only after broker publication; duplicates remain possible."""
        with self.db:
            self.db.execute("UPDATE outbox SET published=1 WHERE id=?", (event_id,))

    def audit(self):
        """Return event identities and attempts without raw reasoning transcripts."""
        return [dict(row) for row in self.db.execute(
            "SELECT id, digest, status, attempts, next_at FROM inbox ORDER BY rowid")]
