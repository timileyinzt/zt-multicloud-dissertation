# =============================================================================
# Azure Infrastructure — AKS Cluster with Istio + Entra ID Integration
#
# NIST SP 800-207 Tenets: T1 (identity), T2 (mTLS), T5 (monitoring), T6 (RBAC)
# =============================================================================

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
  }
}

provider "azurerm" {
  features {}
}

# ── Variables ─────────────────────────────────────────────────────────────────
variable "resource_group_name" {
  default = "zt-dissertation-rg"
}
variable "location" {
  default = "uksouth"
}
variable "cluster_name" {
  default = "zt-aks-cluster"
}
variable "node_count" {
  default = 2
}
variable "vm_size" {
  default = "Standard_B2s"  # Cost-efficient for student/research tier
}

# ── Resource Group ────────────────────────────────────────────────────────────
resource "azurerm_resource_group" "zt" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    Project   = "zt-dissertation"
    ManagedBy = "terraform"
    NistTenet = "T1-T7"
  }
}

# ── AKS Cluster ───────────────────────────────────────────────────────────────
resource "azurerm_kubernetes_cluster" "zt_aks" {
  name                = var.cluster_name
  location            = azurerm_resource_group.zt.location
  resource_group_name = azurerm_resource_group.zt.name
  dns_prefix          = "zt-dissertation"

  # Use Entra ID (AAD) for Kubernetes RBAC — NIST T1: identity-based access
  azure_active_directory_role_based_access_control {
    managed            = true
    azure_rbac_enabled = true
  }

  default_node_pool {
    name       = "system"
    node_count = var.node_count
    vm_size    = var.vm_size

    # Enable node-level OS hardening
    os_sku = "AzureLinux"
  }

  # Managed identity for the cluster (no service principal credentials)
  # NIST T6: No long-lived credentials on cluster identity
  identity {
    type = "SystemAssigned"
  }

  # Network profile — Azure CNI for pod-level networking (required for Istio)
  network_profile {
    network_plugin    = "azure"
    network_policy    = "calico"  # L3/L4 baseline; Istio adds L7 mTLS on top
    load_balancer_sku = "standard"
  }

  # Service mesh — Istio add-on managed by Azure
  # NOTE: Azure managed Istio (ASM) is used here for reliability
  # Alternative: manual Istio install via istioctl (see kubernetes/istio/)
  service_mesh_profile {
    mode                             = "Istio"
    internal_ingress_gateway_enabled = false
    external_ingress_gateway_enabled = true
  }

  # Defender for Containers — runtime threat detection (NIST T5, T7)
  microsoft_defender {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.zt.id
  }

  # OIDC issuer URL — enables Workload Identity (pods get Entra ID tokens)
  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  tags = {
    Project   = "zt-dissertation"
    NistTenet = "T1-T2-T5-T6"
  }
}

# ── Log Analytics Workspace — Centralised logging (NIST T5) ──────────────────
resource "azurerm_log_analytics_workspace" "zt" {
  name                = "zt-dissertation-logs"
  location            = azurerm_resource_group.zt.location
  resource_group_name = azurerm_resource_group.zt.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    Project   = "zt-dissertation"
    NistTenet = "T5"
  }
}

# ── Microsoft Sentinel — SIEM (NIST T5, T7) ──────────────────────────────────
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "zt" {
  workspace_id = azurerm_log_analytics_workspace.zt.id
}

# ── Outputs ───────────────────────────────────────────────────────────────────
output "aks_cluster_name" {
  value = azurerm_kubernetes_cluster.zt_aks.name
}

output "aks_oidc_issuer_url" {
  description = "OIDC issuer URL — use this in AWS/GCP federation trust policies"
  value       = azurerm_kubernetes_cluster.zt_aks.oidc_issuer_url
}

output "log_analytics_workspace_id" {
  value = azurerm_log_analytics_workspace.zt.id
}

output "kube_config" {
  value     = azurerm_kubernetes_cluster.zt_aks.kube_config_raw
  sensitive = true
}
