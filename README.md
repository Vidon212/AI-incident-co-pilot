# AI Incident Triage Copilot

A Python reference project for reviewing AI-proposed incident remediation and
verifying recovery against predefined service reliability targets.

**The model proposes; deterministic policy decides what can proceed.** The copilot
runs as a local CLI, Docker container, or Kubernetes Job. It reads JSON snapshots
and produces review artifacts; model calls, live telemetry collection, human
approval, and production changes remain external integrations.

## What it does

- Normalizes incident context and ranks relevant evidence.
- Validates rollback, scaling, and configuration proposals against safety rules.
- Compares the full proposed plan and raises approval tiers as error budgets shrink.
- Verifies user-facing signals, side effects, and recovery controls after a change.

## Quick start

Clone the repository, then choose Python or Docker. The synthetic examples need
no API key or cloud credentials.

```bash
git clone https://github.com/Vidon212/AI-incident-co-pilot.git
cd AI-incident-co-pilot
```

### Python

Requires **Python 3.11+** and Make. If `python3` is older, specify your interpreter
with `make install PYTHON=python3.13`.

```bash
make install
make triage PYTHON=.venv/bin/python
make verify PYTHON=.venv/bin/python
```

`requirements.txt` installs the local package; runtime code uses only the Python
standard library. Installation needs access to download build dependencies.

### Docker

With Docker running and Make installed:

```bash
make docker-build
make docker-run
make docker-verify
```

Both paths produce `requires_human_approval` for triage and `SUCCESS` for the
separate verification example. These are synthetic results, not authorization to
execute a remediation. Each command prints JSON and exits; there is no web server.

## Documentation

| Guide | Details |
| --- | --- |
| [Architecture and safety](docs/00-architecture-and-safety.md) | Capabilities and trust boundaries |
| [Stage 1: triage](docs/01-stage-1-triage.md) | Structured diagnosis and rollback policy |
| [Stage 2: context](docs/02-stage-2-context.md) | Evidence normalization and ranking |
| [Stage 3: remediation](docs/03-stage-3-remediation.md) | Intent contracts, safety checks, and plan review |
| [Stage 4: verification](docs/04-stage-4-verification.md) | SLO contracts, recovery controls, and error budgets |
| [Local and Kubernetes deployment](docs/05-local-and-kubernetes.md) | Custom inputs, kind, registry images, Jobs, logs, and reruns |

Kubernetes runs the CLI as a batch Job using [`deploy/k8s`](deploy/k8s).
Follow the deployment guide to load or publish the image and select your cluster.

## Development

```bash
make help
make test PYTHON=.venv/bin/python
```

Explore the [source](src/incident_copilot), [examples](examples), and [tests](tests).

## License

Copyright 2026 Vinod Loganathan Ramesh Kumar.
Licensed under the [Apache License 2.0](LICENSE).
