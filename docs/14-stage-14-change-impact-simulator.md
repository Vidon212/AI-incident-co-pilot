# Stage 14: AI change-impact simulator

[Back to README](../README.md)

Session 14 combines a normalized capacity change, the Stage 13 reliability graph,
and operational evidence to screen what could happen before merge. Arithmetic,
topology traversal, controller conditions, and scoring are deterministic. Optional
recorded model commentary explains evidence without changing policy. The local
CLI does not invoke a model, collect live data, post reviews, or mutate production.

## Run locally

```bash
# Growth-sensitive database change with a restart: requires_human_review, 70/100.
make impact PYTHON=.venv/bin/python

# Compare that prediction with independent synthetic post-change measurements.
make impact-feedback PYTHON=.venv/bin/python

# HPA-aware replica screen, including optional recorded model commentary. Exits 0.
PYTHONPATH=src .venv/bin/python -m incident_copilot.impact_cli \
  --change examples/impact/replicas-change.json \
  --context examples/impact/replicas-context.json \
  --graph examples/impact/platform.json \
  --assessment examples/impact/replicas-assessment.json

# Capacity contradiction: block, critical risk. Exits 1.
PYTHONPATH=src .venv/bin/python -m incident_copilot.impact_cli \
  --change examples/impact/node-pool-change.json \
  --context examples/impact/node-pool-context.json \
  --graph examples/impact/platform.json
```

The `connections-change.json` / `connections-context.json` pair provides another
blocked example. All fixtures are synthetic and need no tokens or cloud access.
After `make docker-build`, the same commands work using `docker run --rm
--read-only --network none --cap-drop ALL --security-opt no-new-privileges
ai-incident-copilot:local incident_copilot.impact_cli` followed by the file arguments.
Container CI exercises both a completed human review and a blocked CPU screen.

## Supported change and evidence contract

Each invocation screens **one supported resource update** at exact repository,
base revision, head revision, environment, and graph resource identity. Unknown
fields, unchanged capacity, create/delete operations, and unsupported profiles
are rejected. This is a capacity projection contract, not raw Terraform, Crossplane,
or Kubernetes syntax. An external adapter must normalize complete rendered plans
and route every other changed field/resource through appropriate review; it must
never omit unsupported changes and claim the entire PR passed this screen.

| Profile | Supported before/after field | Demand metrics | Capacity unit |
| --- | --- | --- | --- |
| `node_pool_cpu` | `allocatable_cpu_cores` | Current and peak requested CPU | CPU cores |
| `database_connections` | `max_connections` | Current and peak connections | Connections |
| `service_replicas` | `replicas` | Current and peak RPS, observed safe RPS per pod | Requests per second |

The context binds exact change and graph SHA-256 fingerprints. It includes the
Stage 13 impact query and caller scopes, externally collected schema/plan/policy
statuses, a topology-completeness attestation, telemetry, controller state,
transition details, SLO metadata, historical similarity, and the headroom threshold.
Fingerprints bind inputs; they authenticate neither files nor collectors.

Telemetry identifies its exact resource and includes a collection timestamp,
history-window length, live capacity state, current/peak demand, and a supplied
30-day `growth_fraction`. The peak must be at least current demand, the history
window must cover at least 30 days for a complete screen, and the live state must
match the candidate's before state. Missing, stale, future, or drifted snapshots
cannot produce a usable capacity prediction. A short history marks the analysis
incomplete but does not erase a measured capacity contradiction.

The graph query fixes review time and evidence age, confidence, samples, and
traversal limits. Stage 14 requires relationship confidence ≥0.8, observed samples
≥100, and evidence age policy ≤1 hour. The examples use five minutes. Node/edge
authorization and graph bounds come from Stage 13. Incomplete/truncated topology,
stale visible relationships, unknown preflight checks, or missing reachable SLO
criticality require investigation unless an independent known violation blocks.
The completeness flag is a collector attestation for this change's scope; it
does not turn a snapshot into proof of all real-world dependencies.

## Capacity and controller calculations

All profiles compute current, initial proposed, and effective theoretical capacity;
observed demand; growth-adjusted demand; signed headroom; and deficits:

```text
projected_peak = observed_peak × (1 + supplied_30_day_growth_fraction)
headroom_fraction = (capacity - demand) / capacity
deficit = max(0, demand - capacity)
```

Growth is an explicit scenario assumption, not a learned forecast or a statement
that demand will rise linearly. The models use aggregate quantities and do not
simulate bin-packing, Kubernetes scheduling, database performance, or latency.

| Example | Measured result | Interpretation |
| --- | --- | --- |
| CPU 90 →45, current requests 71, peak 84 | Current headroom 21.1%; proposed current-demand headroom −57.8%; peak deficit 39 cores | Capacity violation; block |
| DB connections 800 →400, peak 610 | Deficit 210 connections | Capacity violation; block |
| DB connections 1,000 →600, peak 540, growth 8% | Projected peak 583.2; headroom 2.8% | Low steady-state margin, plus separate restart risk |
| Replicas 20 →12, peak 7,000 RPS, 420 safe RPS/pod | Initial capacity 5,040; initial peak deficit 1,960; required replicas `ceil(7000/420)=17` | Interpret with the owning controller |

For static replicas, the initial capacity is the ceiling. For an HPA, the context
must provide fresh minimum/maximum replicas and independent `pass` checks for the
scaling signal, node CPU, pod quota, pod IPs, and database capacity. With max 30 and
all checks passing, the example ceiling is 12,600 RPS. It still requires human
review: the screen does not guarantee scaling speed, behavior during the initial
deficit, stabilization, readiness, or rollout safety.

If prerequisites fail or are unknown, usable capacity remains unknown. If even
the HPA's theoretical maximum cannot meet demand, the known ceiling contradiction
blocks regardless of those missing checks. Missing/stale controller state or a
desired replica count outside HPA bounds requires investigation. The simulator
does not silently assume that desired replicas are an HPA maximum.

## Transition risk, propagation, and history

Transition evidence describes `in_place`, `rolling_update`, `restart`,
`replacement`, or `unknown`, plus independently reviewed rollback and optional
canary plan IDs. Unknown/stale transition evidence or an unverified rollback
requires investigation. A plan ID is a platform collector assertion that a real
reviewed plan exists; it cannot be supplied as authority by an LLM. A Terraform
revert alone does not establish that restoration is possible or quick.

Stage 13 evidence paths identify potentially affected services. The first reached
service on a path is first-order; later service callers are second-order. For the
database example:

```text
inventory-db → inventory-api → checkout-api → checkout SLO context
               first-order     second-order
```

Every service entry preserves actual edge citations and usable telemetry evidence.
Templates describe conditional queueing, connection waiting, capacity loss, and
caller error/latency propagation. Retries may amplify load **if configured**; the
screen does not infer retry policies, estimate feedback gain, predict an outage,
or claim the path is demonstrated causality. Ownership, SLO, and incident nodes
remain annotations rather than propagation bridges.

Historical similarity is an independent collector classification using a small
failure-mode vocabulary. It contributes only when the matching incident is linked
by a usable `AFFECTED` edge in the authorized graph neighborhood. Unverified
historical links require investigation and earn no similarity points. Historical
context is not proof that a new change will repeat an incident.

## Reproducible score and policy

The reference rubric is `session14-v1`. Components are explicit in every report:

| Dimension | Points |
| --- | ---: |
| Capacity violation | +40 |
| Low projected headroom, without a known capacity violation | +20 |
| Any affected critical SLO | +20 |
| More than ten affected services | +15 |
| Linked incident with matching failure mode | +15 |
| Rolling update / restart / replacement | +10 / +20 / +30 |
| Independently reviewed rollback plan | −5 |
| Independently reviewed canary plan | −10 |

The sum is clamped to 0–100. Levels are low below 20, medium from 20, high from
50, and critical from 75. This is a tunable example rubric, not a calibrated
incident probability. No points are awarded based on model confidence. Missing
context sets `score_complete: false`; the score is only the known-feature subtotal,
and risk is `unknown` unless a known policy violation blocks the change.

Policy runs independently of the score:

| Decision | Meaning | CLI exit |
| --- | --- | ---: |
| `block` | Failed preflight check or known capacity contradiction | 1 |
| `investigate` | No known violation, but required evidence is incomplete | 1 |
| `requires_human_review` | Supported screen completed; inspect measured risks and controls | 0 |
| Input rejection | Unsupported, malformed, mismatched, or unbound input | 2 |

Canary and rollback credits never cancel a hard capacity block. Even a score of
zero cannot approve a merge. `merge_authorized` and `mutation_authorized` remain
false. This new screen leaves the existing Stage 12 reviewer and remediation
policy unchanged; connecting the reports to a complete PR policy is external work.

Optional model assessments bind to `simulation_sha256` and cite only the target
service's own path edges and usable telemetry. They contain bounded prose rather
than score or approval fields. Citation validation proves linkage, not truth of
the explanation. Model text stays untrusted and downstream renderers must escape
it. The simulation and final report have separate fingerprints so prose cannot
change the bound deterministic prediction.

## Compare prediction with observations

`--outcome` accepts an independent post-change snapshot bound to the exact
simulation, resource, compatible units, and a time after simulation. It returns
measured capacity error and peak-demand error, predicted/observed capacity
constraints, and a flag for a collector-attributed critical incident after a
completed human-review screen. In the example, observed peak 590 exceeds the
growth scenario 583.2 by 6.8 connections, while observed capacity equals 600.

Critical incidents require incident IDs and an explicit external causal
attestation. The comparison cannot establish causality, confirm deployment,
validate an observation window, or compute a calibrated accuracy rate from one
snapshot. It is an evaluation record for a separate reviewed incident cohort.
Live collection, deployment identity verification, comparable workload/window
selection, and model calibration remain external responsibilities.

Collectors must authenticate all provenance, resource mappings, scopes, clock,
plan completeness, observed safe pod capacity, HPA prerequisites, SLO criticality,
historical similarity, and recovery/canary evidence independently of model output.
Raw rendering/plan adapters, live cloud or Kubernetes APIs, model invocation,
GitHub checks, branch protection, approval, merge, and apply are not implemented.
Stage 15 adds a risk-aware autonomy ladder with existing scoped approval gates.

Continue with [Stage 15: autonomy decision engine](15-stage-15-autonomy-decision-engine.md)
or [local and Kubernetes deployment](17-local-and-kubernetes.md).
