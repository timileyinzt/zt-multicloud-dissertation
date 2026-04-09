# Zero Trust Multi-Cloud Architecture — MSc Dissertation Artefact

**Author:** Timileyin Badiru (W24065387)  
**Supervisor:** Dr Ameer Kareem  
**Programme:** MSc Cybersecurity Technology, Northumbria University  
**Module:** LD7236 — Professional Practice in Computing and Digital Technologies Project

---

## Research Context

This repository contains the practical artefact for the dissertation:
*"Securing the Cloud: A Critical Investigation into Zero Trust Architecture Implementation in Multi-Cloud Environments"*

The artefact demonstrates a Zero Trust security architecture deployed across AWS, Microsoft Azure, and Google Cloud Platform (GCP), implementing the seven core tenets of NIST SP 800-207.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│         Identity Control Plane                  │
│   Azure Entra ID (central IdP) + Okta           │
│   ├── AWS: OIDC trust federation                │
│   ├── Azure: Entra ID native                    │
│   └── GCP: Workload Identity Federation         │
└──────────────────┬──────────────────────────────┘
                   │ OPA Policy Decision Point
         ┌─────────┼─────────┐
         ▼         ▼         ▼
      [AWS]     [Azure]    [GCP]
   IAM roles  AKS+Istio  GKE+Istio
   VPC segs   mTLS STRICT mTLS STRICT
   GuardDuty  Sentinel   Cloud SCC
         └─────────┼─────────┘
                   ▼
         Grafana + Loki (unified monitoring)
```

---

## NIST SP 800-207 Tenet Mapping

| Tenet | Description | Implementation |
|-------|-------------|----------------|
| T1 | All data sources treated as resources | Every service requires authenticated identity token |
| T2 | All communication secured | Istio mTLS STRICT mode across all workloads |
| T3 | Per-session access granted | OPA evaluates every request dynamically |
| T4 | Access determined by dynamic policy | Entra ID Conditional Access + OPA Gatekeeper |
| T5 | Monitor all assets | Grafana/Loki aggregating AWS + Azure + GCP logs |
| T6 | Enforce least-privilege | Scoped IAM roles in all three clouds — no wildcards |
| T7 | Collect and improve security posture | GuardDuty + Sentinel + Security Command Centre |

---

## Repository Structure

```
terraform/
  modules/
    identity/           # Reusable identity federation module (all 3 clouds)
    iam-least-privilege/ # Scoped IAM roles per cloud
    monitoring/         # Grafana + Loki deployment
  aws/                  # AWS-specific Terraform
  azure/                # Azure-specific Terraform
  gcp/                  # GCP-specific Terraform

kubernetes/
  istio/
    install/            # Istio operator (STRICT mTLS profile)
    policies/           # AuthorizationPolicies (default deny + allow rules)
  opa/
    policies/           # OPA Rego policies (Gatekeeper constraints)
  demo-app/             # Sample workload for ZT demonstration

docs/
  nist-mapping.md       # Detailed tenet-to-component mapping
  cisa-maturity-mapping.md
  deployment-guide.md

evaluation/
  framework-evaluation.md   # Critical assessment against frameworks
  lab-notebook.md            # Design decisions + rejected alternatives
  practitioner-feedback.md   # Interview participant feedback on artefact
```

---

## Prerequisites

- Terraform >= 1.6.0
- Azure CLI + active subscription
- AWS CLI + credentials configured
- GCP CLI (gcloud) + project configured
- kubectl >= 1.28
- istioctl >= 1.20
- Helm >= 3.12

---

## Deployment Order

```bash
# 1. Identity federation (Phase 1)
cd terraform/modules/identity && terraform init && terraform apply

# 2. Cloud infrastructure (Phase 2)
cd terraform/azure && terraform init && terraform apply
cd terraform/aws   && terraform init && terraform apply
cd terraform/gcp   && terraform init && terraform apply

# 3. Kubernetes / Istio (Phase 3)
istioctl install -f kubernetes/istio/install/istio-operator.yaml
kubectl apply -f kubernetes/istio/policies/
kubectl apply -f kubernetes/opa/

# 4. Monitoring
cd terraform/modules/monitoring && terraform init && terraform apply
```

---

## Lab Notebook

Design decisions, rejected alternatives, and implementation challenges are documented in `evaluation/lab-notebook.md`. This is maintained throughout the project as evidence of iterative research development.

---

## Ethical Statement

This artefact was developed for academic research purposes only. No production credentials, customer data, or proprietary configurations from any employer have been used. All cloud resources are provisioned under personal/student accounts.
