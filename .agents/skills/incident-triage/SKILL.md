---
name: incident-triage
description: Analyze Kubernetes reliability incidents and propose safe, structured GitOps remediation. Use for SRE triage; do not execute production mutations.
---

# Incident Triage

Use this skill to turn read-only incident evidence into an auditable recommendation.

## Evidence

- Gather only the relevant metrics, logs, traces, Kubernetes events, rollout history, dependency health, and GitOps diffs that are available.
- Do not invent observations or infer causation from timing alone. State missing evidence and distinguish correlation from evidence of causality.
- Prefer deployment and version comparisons, readiness or liveness failures, and dependency health over a single correlated signal.

## Diagnosis contract

Return a structured diagnosis with these fields:

```json
{
  "service": "string",
  "severity": "low | medium | high | critical",
  "suspected_cause": "string",
  "confidence": 0.0,
  "evidence": ["string"],
  "recommended_action": "investigate | rollback | no_change",
  "requires_human_approval": true
}
```

- Make confidence reflect the available evidence, not the urgency of the incident.
- Use `investigate` when evidence is incomplete, contradictory, or below the platform's confidence threshold.
- A rollback recommendation is a proposal, not a finding of causality.

## Safety boundary

- Treat the model as a read-only reasoning component. Never execute production mutations, run `kubectl` remediation commands, modify live infrastructure, or obtain production credentials.
- For normal remediation, describe the smallest reviewable GitOps change and require policy evaluation plus human approval before creating it.
- If an emergency path is mentioned, explain its required policy, authorization, audit trail, and reconciliation with Git; do not invoke it.
