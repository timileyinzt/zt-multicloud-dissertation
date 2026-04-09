variable "azure_tenant_id" {
  description = "Azure Entra ID tenant ID — the central IdP"
  type        = string
}

variable "aws_account_id" {
  description = "AWS account ID for trust policy scoping"
  type        = string
}

variable "gcp_project_id" {
  description = "GCP project ID"
  type        = string
}

variable "gcp_pool_id" {
  description = "GCP Workload Identity Pool ID"
  type        = string
  default     = "zt-dissertation-pool"
}

variable "gcp_provider_id" {
  description = "GCP Workload Identity Provider ID"
  type        = string
  default     = "entra-id-provider"
}

variable "aws_zt_role_name" {
  description = "Name of the AWS IAM role for federated workloads"
  type        = string
  default     = "zt-federated-workload-role"
}
