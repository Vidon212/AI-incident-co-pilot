# Stage 15: Autonomy decision engine

[Back to README](../README.md)

Session 15 asks what an agent may do given its diagnosis **and the consequences
of being wrong**. The local evaluator returns one of six capability levels. It
combines typed intent, independently collected ActionRisk, existing remediation
policy, optional recomputed change impact, and scoped approvals. Confidence alone
never grants a higher capability. The evaluator performs no infrastructure action.

## Run the examples

```bash
# Level 5 eligibility: the existing independently preapproved HPA capability.
make autonomy PYTHON=.venv/bin/python

# Level 3: database restart with multiple affected services; recomputes Stage 14.
make autonomy-database PYTHON=.venv/bin/python

# Level 4: known-good rollback with an exact independently approved plan.
PYTHONPATH=src .venv/bin/python -m incident_copilot.autonomy_cli \
  --proposal examples/autonomy/rollback-proposal.json \
  --context examples/autonomy/rollback-context.json

# Level 2 plus immediate human escalation: incompatible migration, low budget.
PYTHONPATH=src .venv/bin/python -m incident_copilot.autonomy_cli \
  --proposal examples/autonomy/rollback-proposal.json \
  --context examples/autonomy/migration-context.json

# Level 2 even at confidence .997: destructive database recreation.
PYTHONPATH=src .venv/bin/python -m incident_copilot.autonomy_cli \
  --proposal examples/autonomy/recreate-proposal.json \
  --context examples/autonomy/recreate-context.json
```

These are synthetic replay snapshots, including their evaluation clocks. The HPA
fixture reuses the Stage 10 evidence and clock instead of claiming its old grant
is current. No cloud credentials or model API key are needed. The existing Docker
image packages the same modules and examples; container CI checks both the Level 5
eligibility artifact and the migration veto. Docker was not run locally during
implementation.

## Autonomy ladder

| Level | Capability | Meaning in this reference implementation |
| --- | --- | --- |
| 0 | `EXPLAIN` | Policy disables this action; explanations only |
| 1 | `INVESTIGATE` | Confidence below .80, stale/future observations, unknown risk, or missing required evidence |
| 2 | `RECOMMEND` | Advisory only: inadequate reversibility, destructive action, migration incompatibility, existing policy denial, or missing control/verification contract |
| 3 | `PREPARE_CHANGE` | Prepare a review bundle; human review/approval remains required |
| 4 | `EXECUTE_WITH_APPROVAL` | Eligible for an external executor only under an exact independent manual approval and existing Stage 3 checks |
| 5 | `EXECUTE_AND_VERIFY` | Eligible for the existing narrowly scoped Stage 10 HPA preapproval workflow |

Levels are capability ceilings, not workflow state transitions or execution tokens.
Even Level 5 returns `execution_authorized: false`, `merge_authorized: false`, and
`eligibility_only: true`. Successful evaluation exits 0 at **every** level; invalid
input exits 2. External consumers must inspect the level and reasons rather than
treating exit 0 as permission to act. Level 3 does not bypass an organization's
existing rules for PR creation; it emits a local preparation artifact.

## Inputs and independent risk dimensions

Proposals carry action, service/resource/namespace/environment, confidence,
desired state, rollback state, verification, and bounded evidence text. Supported
action names are `increase_hpa_max`, `rollback`, `change_capacity`, `change_network`,
`recreate_database`, and `restart_pod`. Each uses a narrow typed desired-state
field; arbitrary commands and model-supplied permission fields are rejected.
Verification uses the existing Stage 3 SLO contract. A missing verification or
rollback contract can be represented, but prevents execution-level eligibility.

The independently supplied context binds the complete proposal fingerprint and
resolved identity. It includes:

- Enabled action policy and the full affected-service set.
- High/low/unknown reversibility, recreation and incompatible-migration facts.
- GitOps ownership, current cluster/downstream headroom, history attempts/successes.
- Remaining error budget, burn rate, change risk, and transition type.
- Trusted review and observation clocks, remediation context, complete plan, and
  an optional independent manual approval receipt.

Risk snapshots must be within five minutes of the supplied review clock and not
from the future. Model confidence stays untrusted even when it passes a threshold.
All source identities, access decisions, topology completeness, operational facts,
history cohorts, review clocks, and policy scopes must be authenticated by live
adapters. Local files cannot authenticate these facts or a receipt's approver.
Fingerprints bind exact inputs; they are not signatures.

The context's `change_risk` is a platform assessment distinct from Stage 3's
approval-tier risk classification. For database connection-capacity changes,
`--impact-bundle` carries Stage 14's change/context/graph sources. The engine
recomputes the screen, checks exact target and desired state, and requires matching
clock, transition, and affected services. A low ActionRisk label cannot downgrade
a high recomputed score, critical SLO impact, or a blocked capacity result. Missing
or incomplete required simulation caps the action at investigation.

HPA limit changes and image rollbacks have no matching Stage 14 capacity profile;
they retain their existing Stage 3 checks instead. VPC routing and database
recreation are advisory profiles; there is no execution adapter for either.
Pod restarts also remain recommendation-only because a reviewed restart/retry
profile has not been implemented. Rollback has manual Level 4 support, but no
automatic Level 5 grant: the current Stage 10 catalog supports HPA increases only.

## Ordered gates and scoped approvals

The ladder evaluates disabled policy and insufficient evidence before execution
eligibility. Recreation, incompatible migrations, and low/unknown reversibility
cap actions at recommendation. Failed existing policy cannot be overridden with
confidence or a receipt. A supported change with high/critical risk, a restart or
replacement, multiple affected services, or critical SLO impact from the simulator
is capped at preparation. These caps apply even if an approval receipt is present.

Level 5 additionally requires all of these reference floors:

| Dimension | Required floor |
| --- | --- |
| Confidence | At least .90 |
| Blast radius | Exactly the single catalog service |
| Reversibility / control path | High reversibility, no recreation/migration veto, GitOps managed |
| History | At least 10 comparable attempts and success rate ≥.95 |
| Cluster / downstream headroom | Each ≥.30 |
| Error budget remaining | Greater than .50 |
| Change / transition | Low change risk; in-place or rolling update |
| Verification / plan | Valid Stage 3 contract, complete exact plan, policy review passes |
| Independent scope | Existing Stage 10 rollout and HPA preapproval review passes |

These are necessary floors, not a replacement for the narrower catalog. Stage 10
may be stricter: its current HPA profile requires confidence greater than .90,
its configured historical-success minimum with no failures, and its own capacity
pattern, rollout evidence, approval binding, expiration, and release scope. Stage 15
checks that the two reviews use the same remediation context, clock, service,
history counts, budget, and headroom. A missing or failing Stage 10 review leaves
the action below Level 5.

Level 4 requires the complete Stage 3 plan review and a receipt binding the exact
proposal, risk/context, plan, verification, and optional simulation fingerprint.
The receipt must be unexpired and at least the Stage 3 required tier. Changing
any bound fact invalidates it. Missing, expired, weak-tier, or mismatched approval
leaves a safe eligible proposal at preparation. Neither receipt grants production
credentials; a live executor must authenticate authorization independently and
recheck current state before applying anything.

## Urgency is separate from permission

Urgency becomes high when the error budget is at or below .10 or burn rate is at
least 10. High urgency plus a risky or non-execution-eligible proposal requests
immediate human escalation. Urgency never adds an autonomy level.

Low budgets also retain Stage 3's existing approval-tier escalation. For example,
4% remaining budget requires incident-commander approval for a supported change;
an old senior-tier receipt is insufficient. An exact stronger receipt may support
Level 4 for an otherwise safe change, but cannot bypass a destructive or migration
veto. Budget pressure also prevents the Level 5 HPA path below its existing floor.

## Authorization includes verification

Level 4/5 artifacts contain a transaction contract before any external action:

```text
Fresh preconditions → reviewed Git change → controller convergence → observe → verify
```

The contract copies the exact verification thresholds, observation timeout, and
rollback state from the proposal, and fingerprints the reviewed preconditions.
It fixes success to closure after independent verification, no improvement to a
request for reviewed Git revert, degradation to an immediate revert request, and
unexpected signals to freeze plus escalation. The ten-minute example timeout
comes from the already reviewed Stage 10 contract; the engine does not invent new
success thresholds after observing outcomes.

This stage emits that contract; it does not run a transaction, observe success,
confirm convergence, deduplicate execution, or initiate a revert. Fresh-state
preconditions, executor identity, serialization, approval expiry/revocation,
controller operations, SLO collection, Stage 4 verification, and authorization of
any recovery action remain external. A failed verification is not blanket
permission to restore an unsafe state. Session 16's Kubernetes reliability
controller is separate future work.

Continue with [local and Kubernetes deployment](16-local-and-kubernetes.md).
