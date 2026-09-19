# AI Incident Triage Copilot

This starter project demonstrates a safety-first reliability pattern:

```
read-only incident context -> structured LLM diagnosis -> deterministic policy -> human-approved GitOps change
```

The code intentionally has **no Kubernetes credentials, no `kubectl` integration, and no production mutation capability**. A language model may propose a diagnosis; the policy engine decides what may happen next.

## Run the example

Requires Python 3.11 or newer.

```bash
PYTHONPATH=src python3 -m incident_copilot \
  --context examples/checkout_503_context.json \
  --diagnosis examples/checkout_503_diagnosis.json
```

The expected decision is `requires_human_approval`, with a proposed Git change to return `checkout-api` to `v2.18.4`.

## Test

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Safety rules in this first iteration

- Diagnoses are schema-validated before policy evaluation.
- Confidence below `0.80` is routed to investigation.
- A rollback is never executed by this service; it requires human approval and yields a GitOps change proposal.
- Other actions default to no change.

The next increment should replace the example diagnosis with an LLM adapter that is constrained to the `Diagnosis` schema, while preserving this policy boundary.
