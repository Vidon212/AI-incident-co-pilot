# GCP transport reference

This Terraform reference provisions Pub/Sub transport and resource-scoped IAM.
It does **not** deploy a running incident investigator. The local SQLite CLI has
no Pub/Sub subscriber, HTTP listener, LLM client, or multi-replica shared store.
See [Stage 11](../../docs/11-stage-11-event-driven-investigator.md) for the adapter
contract and the complete integration checklist.

Use an existing sandbox project with the Pub/Sub API enabled and its service
identity provisioned. Supply existing service accounts; the module creates none
and grants no Terraform, GKE, Cloud SQL, or other mutation credentials.

```hcl
# terraform.tfvars (replace all example emails and the project ID)
project_id                   = "your-sandbox-project"
orchestrator_service_account = "orchestrator@your-sandbox-project.iam.gserviceaccount.com"
operations_service_account   = "incident-dispatcher@your-sandbox-project.iam.gserviceaccount.com"
producer_service_accounts = {
  monitoring        = "normalizer@your-sandbox-project.iam.gserviceaccount.com"
  collectors        = "collectors@your-sandbox-project.iam.gserviceaccount.com"
  investigator      = "investigator@your-sandbox-project.iam.gserviceaccount.com"
  approval-service  = "approvals@your-sandbox-project.iam.gserviceaccount.com"
  gitops-controller = "controller@your-sandbox-project.iam.gserviceaccount.com"
  verifier          = "verifier@your-sandbox-project.iam.gserviceaccount.com"
}
```

Review configuration locally before planning any infrastructure:

```bash
terraform -chdir=deploy/gcp fmt -check
terraform -chdir=deploy/gcp init -backend=false
terraform -chdir=deploy/gcp validate
# With independently authorized sandbox credentials and your own tfvars:
terraform -chdir=deploy/gcp plan
```

The included provider lockfile pins the version used for local validation.
Review provider upgrades in your deployment repository. This reference leaves backend/state management,
regional placement and retention policy review to the deploying organization.
No resources are applied by the local examples or tests.

Each producer may publish only to its own topic. The worker maps its configured
pull subscription to that producer's principal, never a message's `source` or
`attributes.principal`. This boundary depends on auditing existing project/org IAM:
these additive grants do not remove broad permissions that already exist.
The `monitoring` publisher is an external **normalizer**, not raw Cloud Monitoring.
Cloud Monitoring's notification channel and independent pager route remain external.

The Pub/Sub service agent receives publisher on the dead-letter topic and
subscriber on each inbound subscription. Operations gets a real dead-letter
subscription. Its configured transport limit is five best-effort deliveries;
application retry counters are separate and can be stricter. See Google's
[dead-letter documentation](https://docs.cloud.google.com/pubsub/docs/dead-letter-topics).

The outbox dispatcher must route work by an allowlist of orchestrator event types
to separately authenticated downstream APIs, honor `next_at` and `deadline`, and
deduplicate event IDs before side effects. It also handles application-level
`incident.dead_lettered` events and notification requests; these are distinct
from broker dead-letter forwarding. Monitor outbox backlog, subscriber errors,
dead letters, and notification delivery independently of the investigator.
