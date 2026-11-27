# Stage 16: Kubernetes reliability controller

[Back to README](../README.md)

Session 16 turns the prior review artifacts into Kubernetes-shaped desired intent
and deterministic reconciliation. This stage provides a durable local controller
core, three CRD reference schemas, and status-only RBAC. The core records work
requests rather than executing tools, creating PRs, merging, or patching a cluster.
A live Kubernetes watcher/status adapter is separate integration work.

## Run locally

```bash
# Durable success replay; repeating the command preserves status and work IDs.
make controller PYTHON=.venv/bin/python

# Isolated failed-change, independent rollback review, and rollback verification replay.
make controller-rollback PYTHON=.venv/bin/python

# Offline CRD/RBAC rendering; contacts no API server.
make controller-render
```

The success replay reaches `Succeeded`; the rollback replay reaches `RolledBack`.
`CONTROLLER_STATE` selects the SQLite path; `:memory:` is ephemeral. Use a separate
state file for a new scenario or platform binding. Fixtures use the Stage 10/15
synthetic November 2 review clock and preapproval, not a claim of current authority.
Each CLI invocation consumes a finite scenario and exits. There is no watch loop,
HTTP listener, live Kubernetes client, or background dispatcher.

The same module and file arguments run in the existing container. Use `--state
:memory:` with its read-only filesystem, or mount separately secured writable
storage for durable state. Container CI exercises the success replay without
networking. Docker was not run locally during implementation.

## Kubernetes API resources

[`deploy/reliability`](../deploy/reliability) contains namespaced
`reliability.platform.io/v1alpha1` schemas:

| Kind | Spec | Controller-owned status |
| --- | --- | --- |
| `Investigation` | Service/environment, signals, read budget, timeout | Collection, cited hypothesis, evidence references |
| `RemediationProposal` | Exact investigation/policy name and UID, catalog target UID, current HPA ceiling, typed Stage 15 proposal, evidence IDs | Policy/eligibility, Git work correlation, convergence and verification phases |
| `RemediationPolicy` | HPA action scope, confidence, multiplier, headroom, historical success, autonomy cap | Local active-policy marker |

The CRDs expose `/status`, include bounded structural schemas, and use a CEL
transition rule to make spec immutable. See Kubernetes' [CRD and status
documentation](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/)
and [immutable-field guidance](https://kubernetes.io/blog/2022/09/29/enforce-immutability-using-cel/).
Use new named resources for revised intent or policy. The local store also rejects
replacement identity reuse and silently ignores supplied `.status` on registration.

The Role grants reads on these three resource kinds and writes only to
Investigation/RemediationProposal status. It cannot create its own policy, patch
HPAs, read Secrets, or invoke provider APIs. It is a reference Role in `production`,
not a deployed identity; no ServiceAccount, RoleBinding, or Deployment is installed.
Choose a dedicated sandbox namespace and separately review the identity mapping
before any deployment. The manifests were rendered offline, not installed or
validated by a live API server. CEL support and schema acceptance must be checked
against the target server before installation.

Files in `examples/controller` are **API/replay snapshots**, including synthetic
UIDs, generations, resource versions, and creation times. They are not manifests
to apply verbatim. A live adapter obtains those fields from the API server and
resolves real reference UIDs before reconciling. CRDs alone do not run a controller;
the [Kubernetes operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
requires the controller integration as well.

## Durable reconciliation model

The SQLite transaction atomically records status updates, receipt deduplication,
stable work requests, and per-target single-flight ownership. The platform
namespace, distinct producer roles, and authoritative target catalog are bound to
the state file. A different platform cannot reopen that file as if it owned the
same state. Resource specs remain immutable and `observedGeneration`/`specSha256`
identify the reviewed intent.

Each reconcile frame includes resource UID, event ID, expected local revision,
producer principal, trusted receive time, event type, and a typed payload. Different
roles produce collector, investigator, policy-review, GitOps, and verifier events.
An investigator cannot self-authorize a proposal or attest successful execution.
Reusing an event ID with different content is rejected. Exact duplicates return
their recorded receipt without changing status or emitting work again.

The expected local revision models optimistic status concurrency; it is **not** a
Kubernetes resource version. The live adapter must use actual API `resourceVersion`
preconditions, handle `409 Conflict`, reload, and reconcile again. See [Kubernetes
API update semantics](https://kubernetes.io/docs/reference/using-api/api-concepts/).
SQLite is a local durable replay model, not distributed Kubernetes storage or a
proof of exactly-once external effects. A production adapter must coordinate API
status, durable work, authenticated dispatch, and idempotent external workers.

Work IDs bind resource UID, immutable spec, and work purpose. Polling, process
restart, and duplicate delivery cannot enqueue a second Git workflow for the same
intent. A per-target lock also blocks conflicting proposal UIDs from opening
parallel workflows. Locks release only after verified forward or rollback success;
escalated/uncertain in-flight work retains its lock for independent resolution.
The reference exposes recorded outbox work but has no delivery acknowledgment,
retry worker, automatic lock cleanup, or deletion/finalizer implementation.

## Investigation and policy review

An Investigation requests three read-only collectors: Kubernetes, telemetry, and
changes. These logical requests consume three calls within a spec bounded to at
most ten; the timeout is at most five minutes. The current profile has no extra
tool-selection/retry loop. External collectors must enforce their own internal
call and response-size limits. Fresh results reference exactly those collectors.
The investigator records a cause, confidence, and citations to collected evidence.
Completion queues a typed-proposal request; it changes no infrastructure and does
not itself establish that the hypothesis is correct.

The supplied RemediationProposal must match the completed investigation's scope,
confidence, and cited evidence. The referenced RemediationPolicy can tighten the
HPA envelope: confidence at least .90, increase no greater than 2×, cluster headroom
at least .30, historical success at least .95, and a capability ceiling no greater
than Level 5. Environment and service scope must match. A tighter policy vetoes
otherwise valid preapproval.

The reviewer supplies Stage 15 source context plus the existing Stage 10 capability
and replay evidence. The core recomputes eligibility instead of trusting a supplied
`Authorized` status or model-created grant. Level 4/5 eligibility is necessary for
an execution work request; lower levels wait for approval with a review-bundle
request. Policy, review, verification, and source input bindings remain auditable.

Authorization expires no later than its independent grant or five minutes after
the underlying risk observation/review clocks. A later reconciliation rechecks
expiry before dispatch. A live worker must still authenticate authorization,
revocation, policy state, Git revision, target identity, and current preconditions
at the time of action; the recorded request is not an execution credential.

## GitOps ownership and state transitions

The first supported executable profile is an HPA ceiling increase through the
catalog's Argo CD repository/path. It reuses the existing complete-plan, approval,
rollout, and verification gates. No direct Kubernetes or provider patch adapter is
present. Crossplane claims and ExternalSecret references illustrate the same
highest-authoritative-abstraction principle, but need additional catalog/profile
adapters; this stage does not claim to reconcile those resources.

```text
Proposed → Validating → Authorized → Executing → Verifying → Succeeded
                    ↘ AwaitingApproval             ↘ Failed
                                                       ↓ independent reversal review
                                                   RollingBack
                                                       ↓
                                               VerifyingRollback → RolledBack
```

Before requesting Git work, a fresh target UID and live/Git baseline must match
the reviewed preconditions. If Git already contains the desired ceiling but live
state lags, the core enters `AwaitingConvergence` and requests reconciliation
diagnosis instead of another PR. If both already match, it records `NoChange`,
not a claimed recovery. Unexpected baseline drift escalates. A stuck lifecycle
escalates on a later reconcile after a one-hour proposal deadline; there is no
background timer without a scheduler supplying ticks.

GitOps receipts bind the work ID, target UID, converged Git/live values, exact head
SHA, and completion time. Partial convergence waits without another change request.
Convergence moves to `Verifying`, not success. An independent verifier supplies a
complete Stage 4 before/after observation window matching that completion and the
predeclared contract. Stale/future observations cannot establish current recovery.

Failed user-facing criteria request a **new independent rollback safety review**.
Its receipt binds the exact proposal, original operation, Git head, and policy,
must be unexpired, and must attest that reversal is safe. This is a typed local
attestation, not a newly implemented rollback policy or authentication service.
The external reviewer/executor must assess current state and safety independently;
lowering an HPA limit is not automatically safe after capacity has expanded.

Only then does the core request a reviewed Git revert. Its convergence is followed
by another Stage 4 verification window. Failed/inconclusive recovery or an
unexpected critical alert freezes/escalates instead of creating an automatic
rollback loop. `RolledBack` is distinct from successful forward remediation.

## Trust and remaining integrations

Every queued work item explicitly reports `executionAuthorized: false`. Producer
principal strings in replay files are fixture metadata, not authentication. Live
adapters must authenticate isolated identities and provenance, authorize creation
of policy and proposal resources, enforce admission, protect controller-owned
status and storage, redact secrets, and independently validate resource ownership.
Collector, model, Git PR/merge, controller, verifier, and notification workers
remain separate integrations. Existing monitoring and paging must stay available
if the reliability automation is unavailable.

The tests cover forward/rollback lifecycles, persistent replay, duplicate receipts,
revision conflicts, actor separation, immutable specs, target UID substitution,
policy vetoes, deadlines, partial convergence, unexpected signals, and conflicting
proposals. Session 17's broader automation-failure invariants remain future work.

Continue with [local and Kubernetes deployment](17-local-and-kubernetes.md).
