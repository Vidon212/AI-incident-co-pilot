# Run locally and on Kubernetes

[Back to README](../README.md)

The copilot is a batch CLI: it reads JSON, prints a JSON result, and exits.
Run it in Docker for a local evaluation or as a Kubernetes Job for a cluster run.
There is no HTTP server, port, Service, or Ingress. The container evaluates evidence;
it does not apply the remediation it describes.

## Local Python setup

Use Python 3.11 or newer and GNU Make. Run commands from the repository root:

```bash
make help
make install PYTHON=python3.13
make test PYTHON=.venv/bin/python
make triage PYTHON=.venv/bin/python
make context PYTHON=.venv/bin/python
make remediation PYTHON=.venv/bin/python
make verify PYTHON=.venv/bin/python
```

Replace `python3.13` with your installed Python 3.11+ executable. `requirements.txt`
installs the local package from `pyproject.toml`; there are no third-party runtime
dependencies. Installation downloads isolated build tools, so it needs package
index access. The evaluation commands need no API keys or network access.

`make triage` and `make remediation` return review artifacts requiring human
approval. `make verify` returns `SUCCESS` using synthetic rollback observations.
Use `PYTHON` to select an interpreter and `VENV` to change the install directory.

## Local Docker run

Start Docker, then build and run:

```bash
make docker-build
make docker-run
make docker-verify
```

The default image is `ai-incident-copilot:local`. The image installs a wheel built
in a separate build stage, includes the synthetic examples, and runs as UID/GID
10001. The Make targets use a read-only root filesystem, no network, dropped
capabilities, and no privilege escalation. The image build needs network access
for the Python base image and build dependencies.

Select another CLI by supplying its module and arguments after the image name:

```bash
docker run --rm --read-only --network none --cap-drop ALL \
  --security-opt no-new-privileges ai-incident-copilot:local \
  incident_copilot.context_cli --input examples/checkout_incident_evidence.json
```

To evaluate your own snapshots, put `intent.json` and `observations.json` in a
local `inputs/` directory, readable by UID 10001, and mount it read-only:

```bash
docker run --rm --read-only --network none --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount "type=bind,source=$(pwd)/inputs,target=/inputs,readonly" \
  ai-incident-copilot:local incident_copilot.verification_cli \
  --intent /inputs/intent.json --observations /inputs/observations.json \
  > verification-result.json
```

The mounted directory is not baked into the image. Collect snapshots independently
and follow the [trust contract](03-stage-3-remediation.md#trust-and-integration-contract).

## Kubernetes: local cluster

Install Docker, [kind](https://kind.sigs.k8s.io/docs/user/quick-start/), and `kubectl`.
Use a dedicated local cluster for the demo:

```bash
kind create cluster --name copilot
make docker-build
kind load docker-image ai-incident-copilot:local --name copilot
make k8s-render
make k8s-deploy KUBE_CONTEXT=kind-copilot
kubectl --context kind-copilot -n incident-copilot-demo \
  wait --for=condition=complete job/incident-copilot-verify --timeout=120s
kubectl --context kind-copilot -n incident-copilot-demo \
  logs job/incident-copilot-verify
```

The [manifests](../deploy/k8s) create a namespace and a Job running the checkout
rollback verification example. Expected output is `outcome: SUCCESS`. The Job has
resource bounds, no mounted service-account token, a read-only root filesystem,
and no automatic retry. Creating a Job requires your operator's cluster permissions;
the evaluator container itself needs no Kubernetes API access or RBAC grants.

`make k8s-render` is offline. `make k8s-deploy` requires an explicit `KUBE_CONTEXT`
and applies resources to that cluster. It does not build, push, or load the image.

## Kubernetes: registry-backed cluster

Build for the CPU architecture of your cluster and push to a registry you control.
For an amd64 cluster, for example:

```bash
docker buildx build --platform linux/amd64 \
  -t ghcr.io/YOUR_ACCOUNT/ai-incident-copilot:demo-v1 --push .
```

Replace `YOUR_ACCOUNT` and authenticate to your registry first. For mixed-architecture
clusters, publish both `linux/amd64,linux/arm64` with buildx. The repository's CI
builds and smoke-tests images but does not publish them.

Copy `deploy/k8s` to a separate configuration directory and edit the `images` entry
in its `kustomization.yaml` to match the pushed image:

```yaml
images:
  - name: ai-incident-copilot
    newName: ghcr.io/YOUR_ACCOUNT/ai-incident-copilot
    newTag: demo-v1
```

For reproducible deployments, use `digest: sha256:...` in place of `newTag`.
Private registries require an image pull Secret in `incident-copilot-demo` and an
`imagePullSecrets` reference in the Job's pod spec; provision that before running
the Job. Then render and apply your configuration:

```bash
make k8s-render K8S_DIR=/path/to/copilot-config
make k8s-deploy K8S_DIR=/path/to/copilot-config KUBE_CONTEXT=YOUR_CONTEXT
```

This runs the same synthetic snapshot example. For real evidence, mount a
ConfigMap (non-sensitive JSON) or Secret (sensitive JSON) read-only into the Job
and change `--intent` and `--observations` to those mounted paths. The container
does not collect telemetry or wait ten minutes; it verifies that the supplied
snapshots cover the predeclared observation window. Enforce evidence freshness,
provenance, and approval binding in the external workflow.

## Results, reruns, and troubleshooting

| CLI | Exit 0 | Exit 1 | Exit 2 |
| --- | --- | --- | --- |
| Triage | Policy result emitted; inspect `decision` | — | Invalid input |
| Context | Normalized context emitted | — | Invalid input |
| Remediation | `requires_plan` or `requires_human_approval` | `deny` or `investigate` | Invalid input |
| Verification | `SUCCESS` | `FAILED` or `INCONCLUSIVE` | Invalid input |

Docker preserves the CLI exit status. Make may report its own error status for a
failed recipe; read the JSON result as well. Kubernetes marks a nonzero exit as a
failed Job, including valid negative verification outcomes. `backoffLimit: 0`
prevents repeating a deterministic evaluation. A successful Job does not grant
permission to apply a proposed remediation.

If the completion wait times out, inspect the Job and pod before retrying:

```bash
kubectl --context kind-copilot -n incident-copilot-demo get jobs,pods
kubectl --context kind-copilot -n incident-copilot-demo describe job incident-copilot-verify
kubectl --context kind-copilot -n incident-copilot-demo logs job/incident-copilot-verify
```

`ImagePullBackOff` usually means the image was not loaded/pushed or pull credentials
are missing. An architecture mismatch requires rebuilding for the node platform.
For a failed evaluation, inspect its JSON reasons and container exit code.

Job pod templates are immutable, and reapplying a completed Job does not rerun it.
Save its output, then delete only the demo Job and apply again:

```bash
kubectl --context kind-copilot -n incident-copilot-demo \
  logs job/incident-copilot-verify > verification-result.json
kubectl --context kind-copilot -n incident-copilot-demo delete job incident-copilot-verify
make k8s-deploy KUBE_CONTEXT=kind-copilot
```

Finished Jobs are automatically removed after one hour. Keep results externally
if you need an audit trail. To remove the dedicated local demo cluster:

```bash
kind delete cluster --name copilot
```

Background: [Kubernetes Jobs](https://kubernetes.io/docs/concepts/workloads/controllers/job/)
and [Docker multi-stage builds](https://docs.docker.com/build/building/multi-stage/).
