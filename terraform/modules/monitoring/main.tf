# =============================================================================
# Monitoring Module — Grafana + Loki Unified Observability
#
# NIST SP 800-207 Tenet T5: Monitor and validate all assets and traffic
# NIST SP 800-207 Tenet T7: Collect and improve security posture
#
# Design decision: Grafana + Loki over Elastic Stack or Sentinel-only
# Rationale: Grafana is cloud-agnostic; can ingest from AWS CloudWatch,
# Azure Monitor, and GCP Cloud Logging simultaneously via data source plugins.
# Loki is log-aggregation native, lower resource footprint than Elasticsearch.
# Azure Sentinel alone would create a monitoring dependency on Azure availability.
# See lab-notebook.md Entry 3.1
#
# Deployment: Helm chart into the 'monitoring' namespace on AKS
# =============================================================================

terraform {
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.25"
    }
  }
}

# ── Variables ─────────────────────────────────────────────────────────────────
variable "aws_region" {
  default = "eu-west-2"
}
variable "azure_log_analytics_workspace_id" {
  description = "Azure Log Analytics workspace ID for cross-cloud log ingestion"
  type        = string
  default     = ""
}
variable "grafana_admin_password" {
  description = "Grafana admin password — set via environment variable, never hardcoded"
  type        = string
  sensitive   = true
  default     = ""  # Set via TF_VAR_grafana_admin_password env var
}

# ── Namespace ─────────────────────────────────────────────────────────────────
resource "kubernetes_namespace" "monitoring" {
  metadata {
    name = "monitoring"
    labels = {
      # Istio sidecar injection enabled — monitoring traffic also secured by mTLS
      "istio-injection" = "enabled"
    }
  }
}

# ── Loki — Log Aggregation ────────────────────────────────────────────────────
resource "helm_release" "loki" {
  name       = "loki"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "loki-stack"
  version    = "2.10.2"
  namespace  = kubernetes_namespace.monitoring.metadata[0].name

  set {
    name  = "loki.enabled"
    value = "true"
  }
  set {
    name  = "promtail.enabled"
    value = "true"  # Collect logs from all pods in the cluster
  }
  set {
    name  = "loki.persistence.enabled"
    value = "true"
  }
  set {
    name  = "loki.persistence.size"
    value = "10Gi"
  }
  # Retention: 30 days for research purposes
  set {
    name  = "loki.config.table_manager.retention_period"
    value = "720h"
  }
}

# ── Grafana — Unified Dashboard ───────────────────────────────────────────────
resource "helm_release" "grafana" {
  name       = "grafana"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "grafana"
  version    = "7.3.7"
  namespace  = kubernetes_namespace.monitoring.metadata[0].name

  set {
    name  = "adminPassword"
    value = var.grafana_admin_password
  }
  set {
    name  = "service.type"
    value = "LoadBalancer"
  }

  # Pre-configure data sources for multi-cloud log ingestion
  values = [
    <<-YAML
    datasources:
      datasources.yaml:
        apiVersion: 1
        datasources:
          # Loki — local cluster logs (AKS or GKE)
          - name: Loki
            type: loki
            url: http://loki:3100
            access: proxy
            isDefault: true

          # Azure Monitor — Azure-side telemetry
          - name: Azure Monitor
            type: grafana-azure-monitor-datasource
            access: proxy
            jsonData:
              cloudName: azuremonitor
              tenantId: "$${AZURE_TENANT_ID}"
              clientId: "$${AZURE_CLIENT_ID}"
            secureJsonData:
              clientSecret: "$${AZURE_CLIENT_SECRET}"

          # CloudWatch — AWS-side telemetry
          - name: AWS CloudWatch
            type: cloudwatch
            access: proxy
            jsonData:
              defaultRegion: ${var.aws_region}
              authType: default  # Uses pod's federated identity

    # Pre-built dashboards
    dashboardProviders:
      dashboardproviders.yaml:
        apiVersion: 1
        providers:
          - name: zt-dissertation
            folder: Zero Trust Dissertation
            type: file
            options:
              path: /var/lib/grafana/dashboards/zt

    grafana.ini:
      security:
        # Disable anonymous access — NIST T1: identity required
        disable_initial_admin_creation: false
      auth:
        disable_login_form: false
      analytics:
        reporting_enabled: false
        check_for_updates: false
    YAML
  ]

  depends_on = [helm_release.loki]
}

# ── Prometheus — Metrics Collection ──────────────────────────────────────────
resource "helm_release" "prometheus" {
  name       = "prometheus"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  version    = "55.5.1"
  namespace  = kubernetes_namespace.monitoring.metadata[0].name

  set {
    name  = "grafana.enabled"
    value = "false"  # Using our own Grafana deployment above
  }
  set {
    name  = "prometheus.prometheusSpec.scrapeInterval"
    value = "30s"
  }

  # Scrape Istio metrics from all namespaces
  values = [
    <<-YAML
    prometheus:
      prometheusSpec:
        additionalScrapeConfigs:
          - job_name: istio-mesh
            kubernetes_sd_configs:
              - role: endpoints
                namespaces:
                  names: [istio-system, zt-demo]
            relabel_configs:
              - source_labels: [__meta_kubernetes_service_name, __meta_kubernetes_endpoint_port_name]
                action: keep
                regex: istio-pilot;http-monitoring
    YAML
  ]
}

# ── Outputs ───────────────────────────────────────────────────────────────────
output "monitoring_namespace" {
  value = kubernetes_namespace.monitoring.metadata[0].name
}

output "grafana_service_name" {
  value = "grafana.monitoring.svc.cluster.local"
}
