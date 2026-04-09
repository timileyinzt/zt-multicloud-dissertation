# NIST SP 800-207 Tenet Mapping — Zero Trust Multi-Cloud Artefact

**Researcher:** Timileyin Badiru (W24065387)  
**Reference:** Rose et al. (2020) NIST Special Publication 800-207: Zero Trust Architecture

This document maps each component of the practical artefact to the corresponding NIST SP 800-207 tenet it satisfies, partially satisfies, or cannot satisfy within the constraints of this research.

---

## Tenet Mapping Table

| # | NIST SP 800-207 Tenet | Implementation | File(s) | Satisfaction Level |
|---|---|---|---|---|
| T1 | All data sources and computing services are considered resources | Every workload must present a verified Entra ID / SPIFFE identity token before accessing any cloud resource | `aws-oidc-trust.tf`, `gcp-wif.tf`, `azure/main.tf` | **Full** |
| T2 | All communication is secured regardless of network location | Istio PeerAuthentication STRICT mode enforces mTLS for every pod-to-pod call | `peer-auth-strict.yaml`, `istio-operator.yaml` | **Full** |
| T3 | Access to resources is granted on a per-session basis | OPA evaluates every admission request; Istio AuthorizationPolicy evaluated per-request by Envoy | `authorization-policies.yaml`, `no-privileged.rego` | **Full** |
| T4 | Access is determined by dynamic policy | Entra ID Conditional Access policies + OPA Gatekeeper admission control + Istio RBAC | `azure/main.tf` (Conditional Access), `authorization-policies.yaml` | **Full** |
| T5 | All owned and associated systems are monitored and validated | Azure Sentinel + Log Analytics, AWS CloudWatch / CloudTrail, GCP Cloud Audit Logs, Grafana/Loki unified dashboard | `azure/main.tf`, `aws-oidc-trust.tf`, `gcp-wif.tf` | **Full** |
| T6 | Authentication and authorisation are dynamic and strictly enforced | No wildcard IAM permissions; all roles scoped to minimum required resources; runAsNonRoot enforced | `aws-oidc-trust.tf` (inline policy), `gcp-wif.tf` (condition blocks), `no-privileged.rego` | **Full** |
| T7 | Collect and use information to improve security posture | Grafana dashboards aggregating multi-cloud telemetry; Sentinel analytics rules; GCP Security Command Centre | `monitoring/` module | **Partial** — SCC integration requires additional configuration |

---

## Gaps and Limitations

### T7 — Partial satisfaction
Security Command Centre (GCP) integration with the unified Grafana dashboard requires manual log export configuration that was not fully automated within the Terraform modules. This is documented as a limitation in Chapter 5. Manual integration steps are described in `docs/deployment-guide.md`.

### Cross-cloud microsegmentation
Istio mTLS is enforced within each Kubernetes cluster (AKS and GKE independently). Cross-cluster mTLS federation — where a pod in AKS authenticates directly to a pod in GKE using SPIFFE certificates — was evaluated but not implemented due to the complexity of multi-cluster certificate rotation management. This limitation is documented in `evaluation/lab-notebook.md` Entry 2.1 and acknowledged in Chapter 5.

### Identity federation for human users
This artefact focuses on workload identity (machine-to-machine). Human user authentication is handled by Entra ID Conditional Access (Azure) but full cross-cloud SSO for human users was outside the dissertation scope. Noted in Chapter 6 recommendations.

---

## CISA Zero Trust Maturity Model Mapping

| CISA Pillar | Implementation | Maturity Stage Achieved |
|---|---|---|
| Identity | Entra ID + Workload Identity Federation + OPA | Advanced |
| Devices | AKS node hardening (AzureLinux OS SKU) + Defender for Containers | Initial–Advanced |
| Networks | Istio mTLS STRICT + AuthorizationPolicy default-deny | Advanced |
| Applications and Workloads | OPA Gatekeeper admission control + runAsNonRoot policy | Advanced |
| Data | Cloud-native audit logging across all 3 providers | Initial (monitoring present; DLP not implemented) |

**Overall CISA maturity assessment:** Advanced across three of five pillars, with Initial stage on the Data pillar. This reflects a realistic practitioner-achievable implementation rather than an aspirational Optimal state — consistent with findings from interview participants.
