"""Durable local reconciliation core; all external work remains in a transactional outbox."""

from copy import deepcopy
from datetime import timedelta
import json
import sqlite3

from .autonomy import review_autonomy
from .controller_contracts import validate_platform, validate_resource
from .events import timestamp
from .models import ValidationError
from .remediation import identifier, number, object_fields, positive_integer, verification_digest
from .rollout import fingerprint, identifiers
from .verification import evaluate_verification


TERMINAL = {"Completed", "Succeeded", "RolledBack", "Denied", "Escalated", "NoChange"}
EVENT_ROLES = {"tick": "controller", "evidence": "collector", "hypothesis": "investigator",
               "review": "reviewer", "git": "gitops", "verify": "verifier",
               "rollback_review": "reviewer"}


class ReconcileConflict(ValidationError):
    """Reload status before retrying an outdated local revision."""


class ReliabilityController:
    """Persist immutable resources, versioned status, independent receipts, and stable work IDs."""

    def __init__(self, path, platform):
        validate_platform(platform)
        self.platform = deepcopy(platform)
        self.db = sqlite3.connect(path, isolation_level=None, timeout=5)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS resources (
                uid TEXT PRIMARY KEY, kind TEXT, name TEXT, object TEXT, status TEXT,
                revision INTEGER, UNIQUE(kind, name));
            CREATE TABLE IF NOT EXISTS receipts (id TEXT PRIMARY KEY, hash TEXT, body TEXT);
            CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, body TEXT);
            CREATE TABLE IF NOT EXISTS flights (target TEXT PRIMARY KEY, owner TEXT);
        """)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute("SELECT hash FROM metadata").fetchone()
            if row and row[0] != fingerprint(platform):
                raise ValidationError("durable platform binding differs")
            if not row:
                self.db.execute("INSERT INTO metadata VALUES (?)", (fingerprint(platform),))

    def close(self):
        """Close persistence without dispatching any work."""
        self.db.close()

    def resource(self, uid):
        """Return controller-owned status, never model-supplied status."""
        row = self.db.execute("SELECT object, status, revision FROM resources WHERE uid=?",
                              (uid,)).fetchone()
        if row is None:
            raise ValidationError("referenced resource UID does not exist")
        return {**json.loads(row[0]), "status": json.loads(row[1]), "revision": row[2]}

    def resources(self):
        """Return deterministic status snapshots for audit and replay."""
        return [self.resource(row[0]) for row in self.db.execute(
            "SELECT uid FROM resources ORDER BY uid")]

    def pending_work(self):
        """Work is recorded, not delivered or executed by this reference implementation."""
        return [json.loads(row[0]) for row in self.db.execute(
            "SELECT body FROM outbox ORDER BY id")]

    def register(self, resource):
        """Ignore input status and prevent identity replacement or spec mutation in place."""
        validate_resource(resource, self.platform)
        clean = {key: deepcopy(value) for key, value in resource.items() if key != "status"}
        metadata = clean["metadata"]
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute("SELECT object FROM resources WHERE uid=?",
                                  (metadata["uid"],)).fetchone()
            if row:
                old = json.loads(row[0])
                old["metadata"]["resourceVersion"] = metadata["resourceVersion"]
                if old != clean:
                    raise ValidationError("identity/spec is immutable; create a new resource")
                return self.resource(metadata["uid"])
            phase = {"Investigation": "Pending", "RemediationPolicy": "Active",
                     "RemediationProposal": "Proposed"}[clean["kind"]]
            status = {"phase": phase, "observedGeneration": metadata["generation"],
                      "specSha256": fingerprint(clean["spec"]), "toolCalls": 0,
                      "lastTransitionTime": metadata["creationTimestamp"]}
            try:
                self.db.execute("INSERT INTO resources VALUES (?, ?, ?, ?, ?, 0)", (
                    metadata["uid"], clean["kind"], metadata["name"], json.dumps(clean),
                    json.dumps(status)))
            except sqlite3.IntegrityError as error:
                raise ValidationError("kind/name is already bound to another API UID") from error
        return self.resource(metadata["uid"])

    def _emit(self, resource, kind, payload):
        work_id = fingerprint({"uid": resource["metadata"]["uid"],
                               "spec": resource["spec"], "kind": kind})
        work = {"id": work_id, "kind": kind, "resourceUid": resource["metadata"]["uid"],
                "specSha256": resource["status"]["specSha256"], "payload": payload,
                "executionAuthorized": False}
        self.db.execute("INSERT OR IGNORE INTO outbox VALUES (?, ?)", (work_id, json.dumps(work)))
        return work_id

    @staticmethod
    def _phase(resource, phase, reason, now):
        resource["status"].update(phase=phase, reason=reason, lastTransitionTime=now)

    def reconcile(self, frame):
        """Atomically compare status revision, apply a typed receipt, and persist stable work."""
        object_fields(frame, {"id", "uid", "expectedRevision", "principal", "at", "event",
                              "payload"},
                      "reconcile frame")
        for field in ("id", "uid", "principal", "event"):
            identifier(frame[field], field)
        timestamp(frame["at"])
        if frame["event"] not in EVENT_ROLES or frame["principal"] != self.platform[
                "principals"][EVENT_ROLES[frame["event"]]]:
            raise ValidationError("event does not have its required independent producer role")
        if not isinstance(frame["payload"], dict):
            raise ValidationError("event payload must be an object")
        revision = frame["expectedRevision"]
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
            raise ValidationError("expectedRevision must be a nonnegative integer")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            prior = self.db.execute("SELECT hash, body FROM receipts WHERE id=?",
                                    (frame["id"],)).fetchone()
            if prior:
                if prior[0] != fingerprint(frame):
                    raise ValidationError("receipt ID reused for different event content")
                return {**json.loads(prior[1]), "duplicate": True}
            resource = self.resource(frame["uid"])
            if resource["revision"] != revision:
                raise ReconcileConflict("stale revision; reload before retrying")
            if timestamp(frame["at"]) < timestamp(resource["status"]["lastTransitionTime"]):
                raise ValidationError("event time precedes current status")
            before = deepcopy(resource["status"])
            self._dispatch(resource, frame)
            changed = before != resource["status"]
            if changed:
                self.db.execute("UPDATE resources SET status=?, revision=revision+1 WHERE uid=?", (
                    json.dumps(resource["status"]), frame["uid"]))
            receipt = {"id": frame["id"], "phase": resource["status"]["phase"],
                       "revision": revision + int(changed), "changed": changed, "duplicate": False}
            self.db.execute("INSERT INTO receipts VALUES (?, ?, ?)", (
                frame["id"], fingerprint(frame), json.dumps(receipt)))
            return receipt

    def _dispatch(self, resource, frame):
        if resource["status"]["phase"] in TERMINAL or resource["kind"] == "RemediationPolicy":
            return
        timeout = resource["spec"].get("timeoutSeconds", 3600)
        if (timestamp(frame["at"]) - timestamp(resource["metadata"]["creationTimestamp"])
                ).total_seconds() > timeout:
            self._phase(resource, "Escalated", "LifecycleDeadlineExceeded", frame["at"])
            self._emit(resource, "notify_human", {"reason": "lifecycle_timeout"})
            return
        if resource["kind"] == "Investigation":
            self._investigation(resource, frame)
        else:
            handlers = {"tick": self._tick, "review": self._review, "git": self._git,
                        "verify": self._verify, "rollback_review": self._rollback_review}
            if frame["event"] not in handlers:
                raise ValidationError("event is not supported for this resource kind")
            handlers[frame["event"]](resource, frame["payload"], frame["at"])

    def _investigation(self, resource, frame):
        status, spec = resource["status"], resource["spec"]
        event, payload, now = frame["event"], frame["payload"], frame["at"]
        if event == "tick":
            object_fields(payload, set(), "investigation tick")
            if status["phase"] == "Pending":
                for collector in ("kubernetes", "telemetry", "changes"):
                    self._emit(resource, f"collect_{collector}", {"service": spec["service"],
                               "environment": spec["environment"], "readOnly": True})
                status["toolCalls"] = 3
                self._phase(resource, "Collecting", "ReadOnlyEvidenceRequested", now)
        elif event == "evidence" and status["phase"] == "Collecting":
            object_fields(payload, {"evidence"}, "evidence receipt")
            evidence = payload["evidence"]
            if not isinstance(evidence, list) or len(evidence) != 3:
                raise ValidationError("require three independent requested collector results")
            for item in evidence:
                object_fields(item, {"id", "collector", "observedAt"}, "evidence reference")
                identifier(item["id"], "evidence ID")
                identifier(item["collector"], "collector")
                age = (timestamp(now) - timestamp(item["observedAt"])).total_seconds()
                if not 0 <= age <= 300:
                    raise ValidationError("investigation evidence is stale or future")
            identifiers([item["id"] for item in evidence], "unique evidence")
            if {item["collector"] for item in evidence} != {"kubernetes", "telemetry", "changes"}:
                raise ValidationError("results do not match requested collector tools")
            status["evidence"] = evidence
            self._emit(resource, "request_hypothesis", {
                "evidenceIds": [item["id"] for item in evidence]})
            self._phase(resource, "Analyzing", "EvidenceReady", now)
        elif event == "hypothesis" and status["phase"] == "Analyzing":
            object_fields(payload, {"cause", "confidence", "evidenceIds"}, "hypothesis")
            identifier(payload["cause"], "cause")
            number(payload["confidence"], "confidence", 0, 1)
            identifiers(payload["evidenceIds"], "hypothesis evidence")
            if not payload["evidenceIds"] or not set(payload["evidenceIds"]) <= {
                    item["id"] for item in status["evidence"]}:
                raise ValidationError("hypothesis must cite collected evidence")
            status["primaryHypothesis"] = payload
            self._phase(resource, "Completed", "RecordedHypothesisOnly", now)
            self._emit(resource, "request_typed_proposal", {
                "investigationUid": resource["metadata"]["uid"], "service": spec["service"],
                "environment": spec["environment"], "hypothesis": payload})
        else:
            raise ValidationError("investigation event is out of order")

    def _linked(self, resource):
        spec = resource["spec"]
        investigation = self.resource(spec["investigationRef"]["uid"])
        policy = self.resource(spec["policyRef"]["uid"])
        for obj, key, kind in ((investigation, "investigationRef", "Investigation"),
                               (policy, "policyRef", "RemediationPolicy")):
            if obj["kind"] != kind or obj["metadata"]["name"] != spec[key]["name"]:
                raise ValidationError("reference does not identify the exact kind/name/UID")
        if any(investigation["spec"][field] != spec["proposal"][field]
               for field in ("service", "environment")):
            raise ValidationError("investigation scope differs from proposal")
        return investigation, policy

    # Keep independent evidence dimensions explicit in the policy orchestration.
    # pylint: disable-next=too-many-locals
    def _review(self, resource, payload, now):
        if resource["status"]["phase"] not in {"Validating", "AwaitingApproval"}:
            raise ValidationError("proposal is not awaiting policy review")
        object_fields(payload, {"context", "capabilityPlatform", "replay"}, "autonomy sources")
        investigation, policy = self._linked(resource)
        if investigation["status"]["phase"] != "Completed":
            raise ValidationError("investigation has not completed")
        spec, rules = resource["spec"], policy["spec"]
        proposal, context = spec["proposal"], payload["context"]
        hypothesis = investigation["status"]["primaryHypothesis"]
        if (proposal["confidence"] != hypothesis["confidence"]
                or not set(spec["evidenceIds"]) <= set(hypothesis["evidenceIds"])):
            raise ValidationError("proposal confidence/evidence differs from investigation")
        review = review_autonomy(proposal, context,
                                 payload["capabilityPlatform"], payload["replay"])
        if review["autonomy_level"] == 5 and rules["maximumAutonomyLevel"] < 5:
            # A manual-only policy cannot reinterpret an automatic grant as human approval.
            review = review_autonomy(proposal, context)
        age = (timestamp(now) - timestamp(context["evaluated_at"])).total_seconds()
        if not 0 <= age <= 300:
            raise ValidationError("autonomy sources are stale or future")
        catalog = self.platform["targets"][spec["targetUid"]]
        rem = context["remediation_context"]
        if (rem is None or rem["git_path"] != catalog["gitPath"]
                or rem["controller"] != catalog["controller"]
                or rem["current_state"].get("hpa.maxReplicas") != spec["currentMaxReplicas"]):
            raise ValidationError("review differs from authoritative Git path or baseline")
        attempts = context["historical_attempts"]
        allowed = (proposal["environment"] in rules["environments"]
                   and proposal["service"] in rules["services"]
                   and proposal["confidence"] >= rules["minimumConfidence"]
                   and spec["currentMaxReplicas"] < proposal["desired_state"]["hpa.maxReplicas"]
                   <= spec["currentMaxReplicas"] * rules["maximumIncrease"]
                   and context["cluster_headroom"] >= rules["minimumClusterHeadroom"]
                   and attempts > 0 and context["historical_successes"] / attempts
                   >= rules["minimumHistoricalSuccessRate"])
        status = resource["status"]
        status.update(reviewSha256=review["review_sha256"],
                      policySha256=policy["status"]["specSha256"],
                      autonomyLevel=min(review["autonomy_level"], rules["maximumAutonomyLevel"]))
        if not allowed:
            self._phase(resource, "Denied", "PolicyVeto", now)
        elif status["autonomyLevel"] < 4:
            self._phase(resource, "AwaitingApproval", "ExecutionEligibilityNotMet", now)
            self._emit(resource, "prepare_review_bundle", {"reviewSha256": status["reviewSha256"]})
        else:
            expiry = context["approval"]["expires_at"] if status["autonomyLevel"] == 4 else (
                payload["capabilityPlatform"]["preapproval"]["expires_at"])
            status["authorizationExpiresAt"] = min(
                timestamp(expiry), timestamp(context["evaluated_at"]) + timedelta(seconds=300),
                timestamp(context["observed_at"]) + timedelta(seconds=300)).isoformat()
            self._phase(resource, "Authorized", "IndependentEligibilityAndPolicyPass", now)

    def _tick(self, resource, payload, now):
        status, spec = resource["status"], resource["spec"]
        if status["phase"] == "Proposed":
            object_fields(payload, set(), "proposal tick")
            self._phase(resource, "Validating", "PolicyReviewRequired", now)
        elif status["phase"] == "Authorized":
            object_fields(payload, {"targetUid", "gitDesired", "liveValue", "observedAt"},
                          "fresh state")
            self._fresh_target(resource, payload, now)
            if timestamp(now) >= timestamp(status["authorizationExpiresAt"]):
                self._phase(resource, "AwaitingApproval", "AuthorizationExpiredBeforeDispatch", now)
                return
            desired = spec["proposal"]["desired_state"]["hpa.maxReplicas"]
            if payload["gitDesired"] == desired:
                phase = "NoChange" if payload["liveValue"] == desired else "AwaitingConvergence"
                self._phase(resource, phase, "DesiredStateAlreadyExists", now)
                if phase == "AwaitingConvergence":
                    self._emit(resource, "diagnose_reconciliation", {
                        "targetUid": spec["targetUid"]})
                return
            if payload["gitDesired"] != spec["currentMaxReplicas"] or payload["liveValue"] != spec[
                    "currentMaxReplicas"]:
                self._phase(resource, "Escalated", "FreshStatePreconditionFailed", now)
                return
            self.db.execute("INSERT OR IGNORE INTO flights VALUES (?, ?)", (
                spec["targetUid"], resource["metadata"]["uid"]))
            owner = self.db.execute("SELECT owner FROM flights WHERE target=?",
                                    (spec["targetUid"],)).fetchone()[0]
            if owner != resource["metadata"]["uid"]:
                self._phase(resource, "Escalated", "ConflictingRemediationInFlight", now)
                return
            status["operationId"] = self._emit(resource, "request_git_workflow", {
                "targetUid": spec["targetUid"],
                "ownership": self.platform["targets"][spec["targetUid"]],
                "before": spec["currentMaxReplicas"], "after": desired,
                "reviewSha256": status["reviewSha256"], "policySha256": status["policySha256"],
                "verificationSha256": verification_digest(spec["proposal"]["verification"]),
                "authorizationExpiresAt": status["authorizationExpiresAt"]})
            self._phase(resource, "Executing", "GitWorkflowRequestedOnce", now)
        else:
            object_fields(payload, set(), "poll tick")

    @staticmethod
    def _fresh_target(resource, payload, now):
        if payload["targetUid"] != resource["spec"]["targetUid"]:
            raise ValidationError("receipt identifies another target UID")
        for key in ("gitDesired", "liveValue"):
            positive_integer(payload[key], key)
        if not 0 <= (timestamp(now) - timestamp(payload["observedAt"])).total_seconds() <= 300:
            raise ValidationError("target snapshot is stale or future")

    def _git(self, resource, payload, now):
        object_fields(payload, {"targetUid", "gitDesired", "liveValue", "observedAt", "operationId",
                               "completedAt", "headRevision"}, "GitOps receipt")
        self._fresh_target(resource, payload, now)
        status = resource["status"]
        rollback = status["phase"] == "RollingBack"
        if status["phase"] not in {"Executing", "RollingBack"}:
            raise ValidationError("Git receipt is out of lifecycle order")
        operation = status["rollbackOperationId"] if rollback else status["operationId"]
        if payload["operationId"] != operation:
            raise ValidationError("Git receipt belongs to another work request")
        desired = resource["spec"]["currentMaxReplicas"] if rollback else resource[
            "spec"]["proposal"]["desired_state"]["hpa.maxReplicas"]
        if payload["gitDesired"] != desired or payload["liveValue"] != desired:
            return
        if not timestamp(status["lastTransitionTime"]) <= timestamp(payload["completedAt"]) <= (
                timestamp(now)):
            raise ValidationError("completion is outside the active operation window")
        head = payload["headRevision"]
        if (not isinstance(head, str) or len(head) != 40
                or any(char not in "0123456789abcdef" for char in head)):
            raise ValidationError("GitOps receipt requires an exact Git head SHA")
        status.update(completedAt=payload["completedAt"], headRevision=head)
        self._phase(resource, "VerifyingRollback" if rollback else "Verifying",
                    "ConvergedNotVerified", now)
        self._emit(resource, "verify_rollback" if rollback else "verify_recovery", {
            "operationId": operation, "completedAt": status["completedAt"],
            "verification": resource["spec"]["proposal"]["verification"]})

    def _verify(self, resource, payload, now):
        object_fields(payload, {"operationId", "observations"}, "verification receipt")
        status, proposal = resource["status"], resource["spec"]["proposal"]
        rollback = status["phase"] == "VerifyingRollback"
        if status["phase"] not in {"Verifying", "VerifyingRollback"}:
            raise ValidationError("verification is out of lifecycle order")
        operation = status["rollbackOperationId"] if rollback else status["operationId"]
        if payload["operationId"] != operation:
            raise ValidationError("verification belongs to another operation")
        observations = payload["observations"]
        intent = {key: deepcopy(value) for key, value in proposal.items() if key != "service"}
        intent["action"] = "CONFIG_CHANGE"
        if rollback:
            intent["desired_state"], intent["rollback_plan"] = (
                intent["rollback_plan"], intent["desired_state"])
        result = evaluate_verification(intent, observations).to_dict()
        if observations["execution"]["completed_at"] != status["completedAt"]:
            raise ValidationError("verification disagrees with independent GitOps completion")
        if not 0 <= (timestamp(now) - timestamp(observations["after"]["end"])
                     ).total_seconds() <= 300:
            raise ValidationError("verification observations are stale or future")
        status["verification"] = result
        if observations["new_critical_alert"]:
            self._phase(resource, "Escalated", "UnexpectedCriticalSignal", now)
            self._emit(resource, "notify_human", {"reason": "freeze_unexpected_critical_signal"})
        elif result["outcome"] == "SUCCESS":
            self._phase(resource, "RolledBack" if rollback else "Succeeded", "UserSLIVerified", now)
            self.db.execute("DELETE FROM flights WHERE owner=?", (resource["metadata"]["uid"],))
        elif rollback or result["outcome"] == "INCONCLUSIVE":
            self._phase(resource, "Escalated", "RecoveryNotEstablished", now)
            self._emit(resource, "notify_human", {
                "reason": "verification_inconclusive_or_rollback_failed"})
        else:
            self._phase(resource, "Failed", "VerificationFailed", now)
            self._emit(resource, "request_rollback_review", {
                "bindingSha256": self.rollback_binding(resource)})

    @staticmethod
    def rollback_binding(resource):
        """Bind a separately authorized revert to exact spec, operation, Git head, and policy."""
        return fingerprint({"uid": resource["metadata"]["uid"], "spec": resource["spec"],
                            "operationId": resource["status"]["operationId"],
                            "headRevision": resource["status"]["headRevision"],
                            "policySha256": resource["status"]["policySha256"]})

    def _rollback_review(self, resource, payload, now):
        object_fields(payload, {"bindingSha256", "expiresAt", "safeToRevert"}, "rollback approval")
        if resource["status"]["phase"] != "Failed":
            raise ValidationError("rollback review requires a failed forward verification")
        if (payload["safeToRevert"] is not True
                or payload["bindingSha256"] != self.rollback_binding(resource)
                or timestamp(payload["expiresAt"]) <= timestamp(now)):
            self._phase(resource, "Escalated", "RollbackNotIndependentlyAuthorized", now)
            return
        resource["status"]["rollbackOperationId"] = self._emit(
            resource, "request_reviewed_git_revert", {
            "targetUid": resource["spec"]["targetUid"], "bindingSha256": payload["bindingSha256"],
            "authorizationExpiresAt": payload["expiresAt"],
            "before": resource["spec"]["proposal"]["desired_state"]["hpa.maxReplicas"],
            "after": resource["spec"]["currentMaxReplicas"],
            "ownership": self.platform["targets"][resource["spec"]["targetUid"]]})
        self._phase(resource, "RollingBack", "IndependentRollbackReviewAccepted", now)
