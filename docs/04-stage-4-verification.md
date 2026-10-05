# Stage 4: verify remediation against SLOs

[Back to README](../README.md)

Run all commands from the repository root with Python 3.11 or newer. Examples use local JSON fixtures and require no cloud credentials or model API key.

Each remediation intent declares a verification contract before review:
numeric success and failure thresholds, a complete observation window, critical
alert handling, traffic and dependency controls, and optional historical-baseline
guardrails. Thresholds use explicit metric units such as `p95_latency_ms` and
`http_error_rate` (a fraction, so 1% is `0.01`). At least one success threshold
must measure a user-facing SLI. The review artifact includes a SHA-256 fingerprint
of the contract. An external approval service must bind that fingerprint to the
approved intent and executed change; the local CLI cannot authenticate it.

Run the synthetic checkout rollback after a full ten-minute observation window:

```bash
PYTHONPATH=src python3 -m incident_copilot.verification_cli \
  --intent examples/verification/checkout_rollback_intent.json \
  --observations examples/verification/checkout_rollback_observations.json
```

It returns `SUCCESS`: checkout completion rises from 83% to 99.4%, HTTP errors
fall from 17% to 0.6%, and p95 latency falls from 3,800ms to 420ms. Controller
health is recorded, but cannot make failed SLIs pass.

For the payments scaling exercise, run the same CLI with
`examples/remediation/payments_scale_intent.json` and
`examples/verification/payments_scale_observations.json`. It requires p95 and
p99 latency, HTTP errors, throughput, pod CPU, DB connections, and DB latency in
both windows. The example is a hypothetical *post-approval* observation; the
Stage 3 policy still blocks that scale intent while HPA maxReplicas is 10.
If traffic falls beyond the contracted tolerance or dependency latency improves
enough to explain the recovery, the result is `INCONCLUSIVE`, not a claim that
scaling caused it.

Run `examples/verification/checkout_memory_intent.json` with
`examples/verification/checkout_memory_observations.json` to see
`outcome: SUCCESS` and `underlying_problem: unresolved`. OOMKills disappear
and customer-facing signals improve, while 940Mi of memory remains above 2×
the 350Mi historical baseline. This is mitigation evidence, not root-cause proof.
The memory example predeclares an HTTP error target below 2%, so 1.2% passes
that mitigation contract. It would fail the rollback example's stricter 1%
target; a successful mitigation does not establish compliance with a 99.9% SLO.

The verifier returns `FAILED` for a triggered failure threshold, a new critical
alert, unhealthy controller, or unmet success threshold. It returns
`INCONCLUSIVE` for missing signals, a mismatched contract/change, preexisting
SLO health, or a confounded comparison. It never initiates a rollback. CLI exit
codes are `0` for `SUCCESS`, `1` for `FAILED`/`INCONCLUSIVE`, and `2` for
malformed input. These example snapshots are synthetic; production integration
must query read-only observability sources, enforce freshness and provenance,
and bind the approved contract to the exact deployment. Once required signals
and change identity are validated, known failures take precedence over missing
historical baselines or confounded attribution. Infrastructure improvement
alone cannot claim recovery when user-facing success thresholds already passed.

### Error budgets and approval authority

Trusted remediation context may include `error_budget_remaining`, a finite
fraction from 0 to 1 (78% remaining is `0.78`). This is the remaining portion of
the SLO error budget, not the service availability or HTTP success rate. The
collector computes it over the service's SLO accounting window.

| Budget remaining | Required review |
| --- | --- |
| Above 50% | Existing operator or senior tier |
| Above 10%, through 50% | At least engineer; high-risk actions retain senior review |
| 10% or below | Incident commander |
| Field omitted | Existing operator or senior tier, with an unavailable-budget reason |

All changes still require human approval. Budget pressure only raises authority;
it cannot bypass confidence, blast-radius, capacity, or complete-plan checks.
Unknown budget retains the earlier conservative policy for compatibility; it
does not authorize automation. Historical remediation success and automatic
execution remain future integration work.

Run the reviewed HPA proposal with a synthetic 4% budget:

```bash
PYTHONPATH=src python3 -m incident_copilot.remediation_cli \
  --intent examples/remediation/hpa_intent.json \
  --context examples/verification/exhausted_budget_context.json \
  --plan examples/remediation/hpa_plan.json
```

The result requires `incident_commander` approval. Supply this budget through
trusted context, never through model-generated intent, and bind the complete
context and plan in the external approval service.

## Run the other verification examples

Payments scaling (synthetic post-approval evidence):

```bash
PYTHONPATH=src python3 -m incident_copilot.verification_cli \
  --intent examples/remediation/payments_scale_intent.json \
  --observations examples/verification/payments_scale_observations.json
```

Memory mitigation with an unresolved underlying problem:

```bash
PYTHONPATH=src python3 -m incident_copilot.verification_cli \
  --intent examples/verification/checkout_memory_intent.json \
  --observations examples/verification/checkout_memory_observations.json
```
