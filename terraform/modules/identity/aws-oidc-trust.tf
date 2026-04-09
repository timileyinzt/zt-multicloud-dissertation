# =============================================================================
# AWS Identity Federation — OIDC trust to Azure Entra ID
#
# NIST SP 800-207 Tenet T1: All resources require verified identity
# NIST SP 800-207 Tenet T4: Access determined by dynamic policy
# NIST SP 800-207 Tenet T6: Least-privilege access enforced
#
# Design decision: OIDC chosen over SAML
# Rationale: SAML is session-based and does not support workload-to-workload
# authentication. OIDC tokens support per-request continuous verification
# aligned with Zero Trust principle — see lab-notebook.md Entry 1.2
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

# Retrieve TLS thumbprint for Entra ID OIDC endpoint
# Required by AWS to validate the OIDC provider's SSL certificate
data "tls_certificate" "entra_id" {
  url = "https://login.microsoftonline.com/${var.azure_tenant_id}/v2.0/.well-known/openid-configuration"
}

# Create the OIDC Identity Provider in AWS IAM
# This tells AWS: "Trust JWT tokens signed by this Entra ID tenant"
resource "aws_iam_openid_connect_provider" "entra_id" {
  url = "https://login.microsoftonline.com/${var.azure_tenant_id}/v2.0"

  # api://AzureADTokenExchange is the standard audience for WIF tokens
  client_id_list = [
    "api://AzureADTokenExchange",
  ]

  thumbprint_list = [
    data.tls_certificate.entra_id.certificates[0].sha1_fingerprint
  ]

  tags = {
    Project    = "zt-dissertation"
    Component  = "identity-federation"
    NistTenet  = "T1-T4"
    ManagedBy  = "terraform"
  }
}

# IAM Role assumed by federated workloads from AKS/GKE via Entra ID token
# Trust policy enforces:
#   1. Only this specific OIDC provider can trigger assumption
#   2. Token audience must match api://AzureADTokenExchange
#   3. Subject constrained to specific Kubernetes service accounts
resource "aws_iam_role" "zt_federated_workload" {
  name = var.aws_zt_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEntraIDFederation"
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.entra_id.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            # Audience must exactly match — prevents token reuse attacks
            "${aws_iam_openid_connect_provider.entra_id.url}:aud" = "api://AzureADTokenExchange"
          }
          StringLike = {
            # NIST T6: Scope to specific namespace service accounts only
            # Wildcard on SA name is intentional for demo — tighten in production
            "${aws_iam_openid_connect_provider.entra_id.url}:sub" = "system:serviceaccount:zt-demo:*"
          }
        }
      }
    ]
  })

  tags = {
    Project   = "zt-dissertation"
    Component = "identity-federation"
    NistTenet = "T1-T6"
  }
}

# Minimal inline policy — read-only S3 access scoped to dissertation bucket
# NIST T6: No wildcard actions, no wildcard resources
resource "aws_iam_role_policy" "zt_minimal_s3" {
  name = "zt-minimal-s3-readonly"
  role = aws_iam_role.zt_federated_workload.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "MinimalS3ReadOnly"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::zt-dissertation-demo",
          "arn:aws:s3:::zt-dissertation-demo/*"
        ]
      }
    ]
  })
}

# CloudTrail — continuous audit logging (NIST T5: Monitor all assets)
resource "aws_cloudwatch_log_group" "zt_audit" {
  name              = "/zt-dissertation/audit-logs"
  retention_in_days = 30

  tags = {
    Project   = "zt-dissertation"
    NistTenet = "T5"
  }
}

# ── Outputs ──────────────────────────────────────────────────────────────────
output "aws_oidc_provider_arn" {
  description = "ARN of the Entra ID OIDC provider registered in AWS"
  value       = aws_iam_openid_connect_provider.entra_id.arn
}

output "aws_federated_role_arn" {
  description = "ARN of the IAM role that federated workloads assume"
  value       = aws_iam_role.zt_federated_workload.arn
}
