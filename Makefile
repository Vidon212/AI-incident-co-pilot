.DEFAULT_GOAL := help
PYTHON ?= python3
VENV ?= .venv
VENV_PYTHON := $(VENV)/bin/python
IMAGE ?= ai-incident-copilot:local
K8S_DIR ?= deploy/k8s
KUBE_CONTEXT ?=

.PHONY: help install test triage context remediation verify docker-build docker-run docker-verify k8s-render k8s-deploy

help:
	@echo "install        Create a virtual environment and install requirements.txt"
	@echo "test           Run unit tests (Python 3.11+)"
	@echo "triage         Evaluate the checkout rollback proposal"
	@echo "context        Normalize incident evidence"
	@echo "remediation    Review the synthetic HPA plan"
	@echo "verify         Verify the synthetic checkout rollback"
	@echo "docker-build   Build IMAGE (default: ai-incident-copilot:local)"
	@echo "docker-run     Run triage in the container"
	@echo "docker-verify  Run verification in the container"
	@echo "k8s-render     Render Kubernetes manifests without contacting a cluster"
	@echo "k8s-deploy     Apply manifests; requires explicit KUBE_CONTEXT"

install:
	$(PYTHON) -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ is required"'
	$(PYTHON) -m venv $(VENV)
	$(VENV_PYTHON) -m pip install -r requirements.txt

test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

triage:
	PYTHONPATH=src $(PYTHON) -m incident_copilot --context examples/checkout_503_context.json --diagnosis examples/checkout_503_diagnosis.json

context:
	PYTHONPATH=src $(PYTHON) -m incident_copilot.context_cli --input examples/checkout_incident_evidence.json

remediation:
	PYTHONPATH=src $(PYTHON) -m incident_copilot.remediation_cli --intent examples/remediation/hpa_intent.json --context examples/remediation/reviewed_hpa_context.json --plan examples/remediation/hpa_plan.json

verify:
	PYTHONPATH=src $(PYTHON) -m incident_copilot.verification_cli --intent examples/verification/checkout_rollback_intent.json --observations examples/verification/checkout_rollback_observations.json

docker-build:
	docker build -t $(IMAGE) .

docker-run:
	docker run --rm --read-only --network none --cap-drop ALL --security-opt no-new-privileges $(IMAGE)

docker-verify:
	docker run --rm --read-only --network none --cap-drop ALL --security-opt no-new-privileges $(IMAGE) incident_copilot.verification_cli --intent examples/verification/checkout_rollback_intent.json --observations examples/verification/checkout_rollback_observations.json

k8s-render:
	kubectl kustomize $(K8S_DIR)

k8s-deploy:
	@test -n "$(KUBE_CONTEXT)" || { echo "Set KUBE_CONTEXT explicitly, e.g. make k8s-deploy KUBE_CONTEXT=kind-copilot" >&2; exit 2; }
	kubectl --context "$(KUBE_CONTEXT)" apply -k $(K8S_DIR)
