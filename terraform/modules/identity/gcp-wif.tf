# =============================================================================
# GCP Identity Federation — Workload Identity Federation with Azure Entra ID
#
# NIST SP 800-207 Tenet T1: All resources require verified identity
# NIST SP 800-207 Tenet T3: Per-session access, continuous verification
# NIST SP 800-207 Tenet T6: Least-privilege — no long-lived service account keys
#
# Design decision: Workload Identity Federation over service account key files
# Rationale: Key files are static credentials with no automatic expiry.
# Workload Identity Federation issues short-lived tokens per-request,
# directly satisfying Zero Trust's continuous verification requirement.
# See lab-notebook.md Entry 1.1
# =============================================================================

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

# Workload Identity Pool — container for external identity providers
# One pool can hold multiple providers (Entra ID, GitHub Actions, etc.)
resource "google_iam_workload_identity_pool" "zt_pool" {
  project                   = var.gcp_project_id
  workload_identity_pool_id = var.gcp_pool_id
  display_name              = "ZT Dissertation Pool"
  description               = "Workload Identity Pool — Zero Trust multi-cloud dissertation artefact (W24065387)"

  disabled = false
}

# OIDC Provider — configures trust with Azure Entra ID
# GCP will accept tokens issued by this Entra ID tenant
resource "google_iam_workload_identity_pool_provider" "entra_id" {
  project                            = var.gcp_project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.zt_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = var.gcp_provider_id
  display_name                       = "Azure Entra ID (central IdP)"
  description                        = "OIDC provider — Azure Entra ID tenant federation"

  oidc {
    issuer_uri = "https://login.microsoftonline.com/${var.azure_tenant_id}/v2.0"
    # Must match the aud claim in the Entra ID token
    allowed_audiences = ["api://AzureADTokenExchange"]
  }

  # Attribute mapping: translate Entra ID JWT claims to GCP attributes
  # google.subject becomes the principal identifier in IAM bindings
  attribute_mapping = {
    "google.subject"      = "assertion.sub"
    "attribute.tenant"    = "assertion.tid"
    "attribute.namespace" = "assertion['kubernetes.io'].namespace"
    "attribute.sa_name"   = "assertion['kubernetes.io'].serviceaccount.name"
  }

  # NIST T4: Attribute condition — only tokens from this specific tenant
  # Prevents tokens from other Entra ID tenants being accepted
  attribute_condition = "assertion.tid == '${var.azure_tenant_id}'"
}

# GCP Service Account that federated workloads will impersonate
# This SA holds the actual GCP permissions — workloads get a short-lived token
resource "google_service_account" "zt_workload_sa" {
  project      = var.gcp_project_id
  account_id   = "zt-federated-workload"
  display_name = "ZT Federated Workload SA"
  description  = "Service account impersonated by AKS workloads via Entra ID federation"
}

# IAM binding: allow the pool to impersonate the service account
# Scoped to the specific Kubernetes namespace (attribute.namespace = zt-demo)
# NIST T6: Not a wildcard — only workloads in the zt-demo namespace
resource "google_service_account_iam_binding" "wif_binding" {
  service_account_id = google_service_account.zt_workload_sa.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.zt_pool.name}/attribute.namespace/zt-demo"
  ]
}

# Minimal GCP permissions — Cloud Storage read-only on dissertation bucket only
# NIST T6: Predefined role (not custom) at minimum required scope
resource "google_project_iam_member" "zt_storage_viewer" {
  project = var.gcp_project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.zt_workload_sa.email}"

  condition {
    title       = "dissertation-bucket-only"
    description = "Restrict access to dissertation demo bucket"
    expression  = "resource.name.startsWith('projects/_/buckets/zt-dissertation-demo')"
  }
}

# Cloud Audit Logging — Data Access logs for identity events (NIST T5)
resource "google_project_iam_audit_config" "zt_audit" {
  project = var.gcp_project_id
  service = "allServices"

  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
  audit_log_config {
    log_type = "ADMIN_READ"
  }
}

# ── Outputs ──────────────────────────────────────────────────────────────────
output "gcp_pool_name" {
  description = "Full resource name of the Workload Identity Pool"
  value       = google_iam_workload_identity_pool.zt_pool.name
}

output "gcp_provider_name" {
  description = "Full resource name of the OIDC provider"
  value       = google_iam_workload_identity_pool_provider.entra_id.name
}

output "gcp_workload_sa_email" {
  description = "Email of the GCP SA that federated workloads impersonate"
  value       = google_service_account.zt_workload_sa.email
}

output "gcp_wif_audience" {
  description = "WIF audience string — use this in workload credential config files"
  value       = "//iam.googleapis.com/${google_iam_workload_identity_pool.zt_pool.name}/providers/${google_iam_workload_identity_pool_provider.entra_id.workload_identity_pool_provider_id}"
}
