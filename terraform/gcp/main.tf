# =============================================================================
# GCP Infrastructure — GKE Cluster + VPC + Security Command Centre
#
# NIST SP 800-207:
#   T1 — Workload Identity Federation (see modules/identity/gcp-wif.tf)
#   T2 — VPC-native networking + Istio mTLS on GKE
#   T5 — Cloud Logging + Security Command Centre (SCC) for monitoring
#   T6 — Least-privilege node service accounts, no default SA permissions
#
# Design decision: GKE Autopilot was evaluated but rejected.
# Rationale: Autopilot restricts node-level configuration that Istio requires,
# specifically the ability to set system call profiles and mount host paths
# for the Envoy sidecar injector. Standard mode GKE provides full control.
# See lab-notebook.md for full decision record.
# =============================================================================

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# ── Variables ─────────────────────────────────────────────────────────────────
variable "gcp_project_id" {
  description = "GCP project ID"
  type        = string
}
variable "gcp_region" {
  default = "europe-west2"  # London
}
variable "cluster_name" {
  default = "zt-gke-cluster"
}
variable "node_count" {
  default = 2
}

# ── VPC — Custom network for GKE (no default VPC) ────────────────────────────
# NIST T2: Avoid using the default GCP network which has permissive firewall rules
resource "google_compute_network" "zt" {
  name                    = "zt-dissertation-vpc"
  auto_create_subnetworks = false  # Explicit subnet control
  mtu                     = 1460

  description = "Zero Trust dissertation VPC — no auto subnets, explicit firewall rules"
}

resource "google_compute_subnetwork" "zt_gke" {
  name          = "zt-gke-subnet"
  ip_cidr_range = "10.20.0.0/22"
  region        = var.gcp_region
  network       = google_compute_network.zt.id

  # Secondary ranges required for GKE pods and services
  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.21.0.0/16"
  }
  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.22.0.0/20"
  }

  # Enable VPC Flow Logs — NIST T5: network-level monitoring
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }

  private_ip_google_access = true  # Allow private nodes to reach Google APIs
}

# ── Firewall Rules — Default-deny then explicit allow (NIST T2, T6) ───────────
# Delete the default-allow-internal rule if it exists, then add specific rules

resource "google_compute_firewall" "deny_all_ingress" {
  name    = "zt-deny-all-ingress"
  network = google_compute_network.zt.name
  priority = 65534

  description = "ZT: Deny all ingress by default — NIST T2 microsegmentation"

  deny {
    protocol = "all"
  }
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "allow_istio_control_plane" {
  name    = "zt-allow-istio-cp"
  network = google_compute_network.zt.name
  priority = 1000

  description = "Allow Istio control plane webhook — required for sidecar injection"

  allow {
    protocol = "tcp"
    ports    = ["15017", "15010", "15012", "15014"]
  }
  direction   = "INGRESS"
  source_ranges = ["10.20.0.0/22"]
  target_tags   = ["gke-node"]
}

resource "google_compute_firewall" "allow_internal_mtls" {
  name    = "zt-allow-internal-mtls"
  network = google_compute_network.zt.name
  priority = 900

  description = "Allow Istio mTLS traffic between nodes — ZT enforced at service mesh layer"

  allow {
    protocol = "tcp"
    ports    = ["15001", "15006", "15008", "9080"]  # Envoy inbound/outbound + app
  }
  direction   = "INGRESS"
  source_tags = ["gke-node"]
  target_tags = ["gke-node"]
}

# ── Node Service Account — Least-Privilege (NIST T6) ──────────────────────────
# GKE nodes should NOT use the default compute service account
# Default SA has broad Editor permissions — violates least-privilege
resource "google_service_account" "gke_node_sa" {
  account_id   = "zt-gke-node-sa"
  display_name = "ZT GKE Node Service Account"
  description  = "Least-privilege SA for GKE nodes — no default compute permissions"
}

# Minimal roles required by GKE nodes
resource "google_project_iam_member" "gke_log_writer" {
  project = var.gcp_project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.gke_node_sa.email}"
}

resource "google_project_iam_member" "gke_metric_writer" {
  project = var.gcp_project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.gke_node_sa.email}"
}

resource "google_project_iam_member" "gke_artifact_reader" {
  project = var.gcp_project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.gke_node_sa.email}"
}

# ── GKE Cluster ───────────────────────────────────────────────────────────────
resource "google_container_cluster" "zt_gke" {
  name     = var.cluster_name
  location = var.gcp_region

  network    = google_compute_network.zt.name
  subnetwork = google_compute_subnetwork.zt_gke.name

  # Remove default node pool — we create a custom one below
  remove_default_node_pool = true
  initial_node_count       = 1

  # VPC-native networking (alias IPs) — required for Istio pod-level policies
  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  # Private cluster — nodes have no public IPs
  # NIST T2: No direct internet access to workload nodes
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false  # Public endpoint kept for kubectl access in research
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  # Workload Identity — enables pods to impersonate GCP service accounts
  # NIST T1: Pods get cryptographic identity, not static credentials
  workload_identity_config {
    workload_pool = "${var.gcp_project_id}.svc.id.goog"
  }

  # Binary Authorisation — only signed container images (NIST T4)
  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }

  # Shielded nodes — verifiable node integrity (NIST T7)
  enable_shielded_nodes = true

  # Intra-node visibility — Istio can monitor pod-to-pod traffic on same node
  enable_intranode_visibility = true

  # Network policy — Calico L3/L4 as baseline; Istio adds L7 mTLS on top
  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  # Istio — managed service mesh via Anthos Service Mesh
  # Note: ASM is preferred over open-source Istio on GKE for production
  # For this research artefact we use the managed channel
  addons_config {
    http_load_balancing {
      disabled = false
    }
    horizontal_pod_autoscaling {
      disabled = false
    }
    gcs_fuse_csi_driver_config {
      enabled = true
    }
  }

  # Security posture scanning (NIST T7)
  security_posture_config {
    mode               = "BASIC"
    vulnerability_mode = "VULNERABILITY_BASIC"
  }

  # Cluster-level logging (NIST T5)
  logging_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "WORKLOADS",
      "APISERVER",
      "SCHEDULER",
      "CONTROLLER_MANAGER"
    ]
  }

  monitoring_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "APISERVER",
      "WORKLOADS"
    ]
    managed_prometheus {
      enabled = true  # Google Managed Prometheus — feeds Grafana
    }
  }
}

# ── GKE Node Pool ─────────────────────────────────────────────────────────────
resource "google_container_node_pool" "zt_nodes" {
  name       = "zt-node-pool"
  location   = var.gcp_region
  cluster    = google_container_cluster.zt_gke.name
  node_count = var.node_count

  node_config {
    machine_type = "e2-standard-2"  # 2 vCPU, 8GB — sufficient for Istio sidecars
    disk_size_gb = 50
    disk_type    = "pd-ssd"

    # Use custom least-privilege SA — not default compute SA
    service_account = google_service_account.gke_node_sa.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]

    # Shielded instance config (NIST T7)
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    # Workload Identity on nodes
    workload_metadata_config {
      mode = "GKE_METADATA"  # Prevents pods accessing node metadata
    }

    labels = {
      project   = "zt-dissertation"
      nist-tenet = "T1-T2-T5-T6"
    }

    tags = ["gke-node", "zt-dissertation"]
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  upgrade_settings {
    max_surge       = 1
    max_unavailable = 0
  }
}

# ── Outputs ───────────────────────────────────────────────────────────────────
output "gke_cluster_name" {
  value = google_container_cluster.zt_gke.name
}

output "gke_cluster_endpoint" {
  value     = google_container_cluster.zt_gke.endpoint
  sensitive = true
}

output "gke_workload_identity_pool" {
  value = "${var.gcp_project_id}.svc.id.goog"
}

output "gke_node_sa_email" {
  value = google_service_account.gke_node_sa.email
}
