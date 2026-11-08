terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0, < 8.0"
    }
  }
}

provider "google" {
  project = var.project_id
}

variable "project_id" {
  type        = string
  description = "Existing GCP project with the Pub/Sub API and service identity provisioned."
}

variable "producer_service_accounts" {
  type        = map(string)
  description = "Existing service account emails, one independent identity per producer trust domain."
  validation {
    condition = (
      toset(keys(var.producer_service_accounts)) == toset([
        "monitoring", "collectors", "investigator", "approval-service", "gitops-controller", "verifier"
      ]) && length(distinct(values(var.producer_service_accounts))) == 6 &&
      alltrue([for email in values(var.producer_service_accounts) : endswith(email, ".iam.gserviceaccount.com")])
    )
    error_message = "Supply six distinct service account emails for the documented producer roles."
  }
}

variable "orchestrator_service_account" {
  type        = string
  description = "Existing identity used only by the trusted orchestrator and outbox publisher."
}

variable "operations_service_account" {
  type        = string
  description = "Trusted external dispatcher/DLQ operator; never the model investigator."
}

data "google_project" "current" {}

locals {
  pubsub_service_agent = "service-${data.google_project.current.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

# Separate topics make the subscription's authenticated provenance meaningful.
# Never multiplex approvals and model output on a shared producer topic.
resource "google_pubsub_topic" "inbound" {
  for_each = var.producer_service_accounts
  name     = "incident-${each.key}"
}

resource "google_pubsub_topic_iam_member" "producer" {
  for_each = var.producer_service_accounts
  topic    = google_pubsub_topic.inbound[each.key].name
  role     = "roles/pubsub.publisher"
  member   = "serviceAccount:${each.value}"
}

resource "google_pubsub_topic" "dead_letters" {
  name = "incident-dead-letters"
}

resource "google_pubsub_topic_iam_member" "dead_letter_publisher" {
  topic  = google_pubsub_topic.dead_letters.name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:${local.pubsub_service_agent}"
}

resource "google_pubsub_subscription" "inbound" {
  for_each                   = var.producer_service_accounts
  name                       = "incident-orchestrator-${each.key}"
  topic                      = google_pubsub_topic.inbound[each.key].id
  ack_deadline_seconds       = 30
  message_retention_duration = "604800s"
  expiration_policy { ttl = "" }
  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "300s"
  }
  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dead_letters.id
    max_delivery_attempts = 5 # Pub/Sub best effort; local application counters are independent.
  }
  depends_on = [google_pubsub_topic_iam_member.dead_letter_publisher]
}

resource "google_pubsub_subscription_iam_member" "orchestrator" {
  for_each     = var.producer_service_accounts
  subscription = google_pubsub_subscription.inbound[each.key].name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${var.orchestrator_service_account}"
}

resource "google_pubsub_subscription_iam_member" "dead_letter_forwarder" {
  for_each     = var.producer_service_accounts
  subscription = google_pubsub_subscription.inbound[each.key].name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${local.pubsub_service_agent}"
}

resource "google_pubsub_subscription" "dead_letters" {
  name                       = "incident-dead-letters-operations"
  topic                      = google_pubsub_topic.dead_letters.id
  message_retention_duration = "604800s"
  expiration_policy { ttl = "" }
}

resource "google_pubsub_subscription_iam_member" "dead_letter_reader" {
  subscription = google_pubsub_subscription.dead_letters.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${var.operations_service_account}"
}

resource "google_pubsub_topic" "outbox" {
  name = "incident-work-outbox"
  lifecycle {
    precondition {
      condition = (
        !contains(values(var.producer_service_accounts), var.orchestrator_service_account) &&
        !contains(values(var.producer_service_accounts), var.operations_service_account) &&
        var.orchestrator_service_account != var.operations_service_account
      )
      error_message = "Keep the orchestrator, dispatcher, and all producer identities independent."
    }
  }
}

resource "google_pubsub_topic_iam_member" "outbox_publisher" {
  topic  = google_pubsub_topic.outbox.name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:${var.orchestrator_service_account}"
}

resource "google_pubsub_subscription" "work" {
  name                       = "incident-work-dispatcher"
  topic                      = google_pubsub_topic.outbox.id
  message_retention_duration = "604800s"
  expiration_policy { ttl = "" }
}

resource "google_pubsub_subscription_iam_member" "dispatcher" {
  subscription = google_pubsub_subscription.work.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${var.operations_service_account}"
}

output "inbound_subscriptions" {
  value = { for role, subscription in google_pubsub_subscription.inbound : role => subscription.id }
}

output "outbox_topic" {
  value = google_pubsub_topic.outbox.id
}

output "dead_letter_subscription" {
  value = google_pubsub_subscription.dead_letters.id
}
