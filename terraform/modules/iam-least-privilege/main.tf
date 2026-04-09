# =============================================================================
# IAM Least-Privilege Module — Shared policy definitions across clouds
#
# NIST SP 800-207 Tenet T6: Enforcement of least-privilege access
#
# This module documents the IAM policy design decisions in one place,
# ensuring consistent least-privilege principles across AWS, Azure, and GCP.
# Individual cloud implementations reference these principles.
#
# Design principle applied throughout:
#   1. No wildcard actions (*) in any policy statement
#   2. No wildcard resources (*) unless unavoidable (e.g. IAM PassRole)
#   3. Condition blocks used wherever supported to further restrict scope
#   4. Separate roles per workload — no shared service identities
#   5. Time-bound permissions where the cloud supports it
# =============================================================================

# ── AWS: Example scoped role for dissertation demo workload ───────────────────
# (Called from terraform/aws/main.tf via the identity module outputs)

variable "aws_demo_bucket_arn" {
  description = "ARN of the S3 bucket the demo workload accesses"
  type        = string
  default     = "arn:aws:s3:::zt-dissertation-demo"
}

variable "aws_oidc_provider_arn" {
  description = "ARN of the Entra ID OIDC provider in AWS"
  type        = string
  default     = ""
}

variable "azure_tenant_id" {
  description = "Azure Entra ID tenant ID"
  type        = string
  default     = ""
}

# Documenting the IAM design decisions as local values for reference
locals {
  # These are the principles applied — referenced in dissertation Chapter 4
  iam_design_principles = {
    no_wildcard_actions   = "Every IAM statement uses specific action names"
    no_wildcard_resources = "Resources scoped to ARN-level specificity"
    condition_blocks      = "Conditions further restrict when rules apply"
    per_workload_roles    = "One role per workload, never shared"
    oidc_not_keys         = "OIDC federation used — no long-lived access keys"
  }

  # Rejected alternatives documented for dissertation methodology
  rejected_iam_approaches = {
    admin_role         = "AdministratorAccess policy — rejected: violates T6"
    poweruser_role     = "PowerUserAccess — rejected: too broad for workload"
    static_access_keys = "IAM access keys — rejected: static credentials violate ZT continuous auth"
    shared_role        = "Single role for all workloads — rejected: blast radius too large"
  }
}

output "iam_principles" {
  description = "IAM design principles applied — reference for dissertation Chapter 4"
  value       = local.iam_design_principles
}

output "rejected_approaches" {
  description = "IAM approaches evaluated and rejected — reference for lab notebook"
  value       = local.rejected_iam_approaches
}
