# AI Incident Triage Copilot

A Python reference project for turning incident evidence and AI-generated diagnoses
into reviewable remediation proposals, then verifying recovery against predefined
service reliability targets.

**The model proposes; deterministic policy decides what can proceed.** The local
CLIs consume JSON fixtures. Production changes require an external human-approved
GitOps workflow.

## What it does

- Normalizes incident context and ranks relevant evidence.
- Validates rollback, scaling, and configuration proposals against safety rules.
- Compares the full proposed plan and raises approval tiers as error budgets shrink.
- Verifies user-facing signals, side effects, and recovery controls after a change.

## Quick start

Requires **Python 3.11+**. Run from the repository root; no API key or cloud
credentials are needed for these examples.

```bash
git clone https://github.com/Vidon212/AI-incident-co-pilot.git
cd AI-incident-co-pilot

# Review a proposed checkout rollback.
PYTHONPATH=src python3 -m incident_copilot \
  --context examples/checkout_503_context.json \
  --diagnosis examples/checkout_503_diagnosis.json

# Verify a separate synthetic rollback against its predeclared contract.
PYTHONPATH=src python3 -m incident_copilot.verification_cli \
  --intent examples/verification/checkout_rollback_intent.json \
  --observations examples/verification/checkout_rollback_observations.json
```

Expected results: `requires_human_approval` for the proposal and `SUCCESS` for
the verification example. These are local demonstration artifacts, not execution
authorization or evidence from a live service.

## Documentation

| Guide | Details |
| --- | --- |
| [Architecture and safety](docs/00-architecture-and-safety.md) | Capabilities, trust boundaries, and external integrations |
| [Stage 1: triage](docs/01-stage-1-triage.md) | Structured diagnosis and rollback policy |
| [Stage 2: context](docs/02-stage-2-context.md) | Evidence normalization and ranking |
| [Stage 3: remediation](docs/03-stage-3-remediation.md) | Runnable examples, intent schema, policy checks, and plan review |
| [Stage 4: verification](docs/04-stage-4-verification.md) | SLO contracts, control signals, mitigation outcomes, and error budgets |

## Development

Run the test suite:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Implementation lives in [`src/incident_copilot`](src/incident_copilot), with
[`examples`](examples) and [`tests`](tests) alongside it. The project does not call
an LLM or mutate production; live collection, approval, and execution are external
integrations.
