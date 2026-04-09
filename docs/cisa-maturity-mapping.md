# CISA Zero Trust Maturity Model v2.0 — Artefact Mapping

**Reference:** CISA (2023) Zero Trust Maturity Model Version 2.0

The CISA ZTM v2.0 defines four maturity stages across five pillars:
- **Traditional** — Manual, siloed, static
- **Initial** — Some automation, cross-pillar awareness beginning
- **Advanced** — Integrated, policy-driven, automated in most areas  
- **Optimal** — Fully automated, self-healing, continuous improvement

---

## Pillar-by-Pillar Assessment

### Pillar 1: Identity

| CISA Criterion | Implementation | Stage |
|---|---|---|
| Enterprise-wide identity system | Azure Entra ID as central IdP | Advanced |
| MFA for all users | Entra ID Conditional Access with MFA required | Advanced |
| Phishing-resistant MFA | FIDO2/Passkey via Entra ID | Initial |
| Machine identity management | SPIFFE/SPIRE via Istio for workloads | Advanced |
| Continuous identity validation | OPA per-request evaluation + Entra ID token validation | Advanced |
| Risk-based authentication | Entra ID Identity Protection (risk scoring) | Initial |

**Overall Identity Stage: Advanced**

---

### Pillar 2: Devices

| CISA Criterion | Implementation | Stage |
|---|---|---|
| Device inventory | Azure Defender for Cloud (AKS nodes) | Initial |
| Device compliance | AzureLinux OS SKU + Shielded Nodes (GKE) | Advanced |
| Device health signals | Shielded instance integrity monitoring (GKE) | Advanced |
| Real-time device posture | Node security scanning via Defender for Containers | Initial |

**Overall Devices Stage: Initial–Advanced**

*Note: This pillar is less complete in this artefact because the research focus is on workload and network ZT. Device management for end-user devices is out of scope.*

---

### Pillar 3: Networks

| CISA Criterion | Implementation | Stage |
|---|---|---|
| Network segmentation | VPC security groups (AWS) + VPC firewall rules (GCP) + AKS network policy | Advanced |
| Encrypted communications | Istio mTLS STRICT — all pod-to-pod traffic encrypted | Advanced |
| Micro-perimeters | Istio AuthorizationPolicy per-service rules | Advanced |
| Traffic inspection | Istio access logs + Envoy metrics in Grafana | Advanced |
| Software-defined networking | Azure CNI + Calico (AKS), VPC-native (GKE) | Advanced |
| Automated policy enforcement | OPA Gatekeeper + Istio admission webhook | Advanced |

**Overall Networks Stage: Advanced**

---

### Pillar 4: Applications and Workloads

| CISA Criterion | Implementation | Stage |
|---|---|---|
| Application inventory | Kubernetes labels (app, owner, version) enforced by OPA | Initial |
| Authorisation per-request | Istio AuthorizationPolicy evaluated per request | Advanced |
| Secure CI/CD | Not implemented (out of scope for this artefact) | Traditional |
| Runtime protection | Defender for Containers + GKE Security Posture | Initial |
| Non-root workloads | OPA ZtNoPrivilegedContainers policy enforced | Advanced |
| Immutable infrastructure | Kubernetes Deployments (not StatefulSets or manual pods) | Advanced |

**Overall Applications and Workloads Stage: Advanced**

*Note: CI/CD security (secure build pipelines, image signing) is acknowledged as a gap. This is documented in Chapter 5 and Chapter 6 recommendations.*

---

### Pillar 5: Data

| CISA Criterion | Implementation | Stage |
|---|---|---|
| Data inventory and classification | Not implemented — out of scope | Traditional |
| Data access logging | CloudTrail (AWS) + Azure Audit Logs + GCP Cloud Audit Logs | Initial |
| Data encryption at rest | S3 SSE-AES256 + Azure Storage encryption + GCP default encryption | Advanced |
| Data Loss Prevention | Not implemented | Traditional |
| Rights management | IAM scoped to specific bucket ARNs only | Initial |

**Overall Data Stage: Initial**

*Note: Data classification and DLP are acknowledged gaps. The dissertation research focus is on identity and network ZT, not data governance. This is discussed honestly in Chapter 5.*

---

## Overall Maturity Summary

| Pillar | Stage Achieved | Key Strength | Key Gap |
|---|---|---|---|
| Identity | Advanced | Workload Identity Federation across 3 clouds | Phishing-resistant MFA not fully deployed |
| Devices | Initial–Advanced | Shielded nodes, Defender for Containers | End-user device management out of scope |
| Networks | Advanced | Global STRICT mTLS, default-deny AuthPolicy | Cross-cluster mTLS federation not completed |
| Apps and Workloads | Advanced | OPA admission control, non-root enforcement | CI/CD pipeline security not implemented |
| Data | Initial | Multi-cloud audit logging in place | Classification and DLP not implemented |

**Weighted assessment: Advanced across three pillars, Initial on two.**

This reflects a realistic practitioner-achievable ZT implementation — not an aspirational Optimal state. The gaps are acknowledged transparently and form the basis of Chapter 5 critical evaluation and Chapter 6 recommendations.

---

## Comparison with Interview Findings

The artefact maturity assessment will be compared against practitioner-reported maturity levels from the primary qualitative research (Chapter 5). Initial analysis suggests practitioners commonly report:

- Identity pillar at Initial–Advanced (consistent with this artefact)
- Networks pillar at Initial (practitioners report Istio adoption is still uncommon)
- Data pillar at Traditional (most organisations have not begun data classification for ZT)

Where the artefact exceeds typical practitioner-reported maturity (particularly in the Networks pillar), this divergence will be discussed as a finding — the academic artefact achieved higher maturity than is typical in production environments, which speaks to the implementation complexity identified in the literature review.
