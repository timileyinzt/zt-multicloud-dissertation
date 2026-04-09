# Framework Evaluation — Critical Assessment of Artefact

**Researcher:** W24065387 — Timileyin Badiru  
**Purpose:** Critical evaluation of the practical artefact against NIST SP 800-207 and CISA ZTM v2.0. This document feeds directly into dissertation Chapter 5 (Evaluation and Implications).

---

## 1. What Was Achieved

### Identity Federation (Phase 1)
The three-cloud identity federation model — Entra ID as central IdP, AWS OIDC trust, GCP Workload Identity Federation — successfully demonstrated that workloads in AKS can obtain short-lived, scoped credentials for AWS S3 and GCP Cloud Storage without any long-lived keys. This directly satisfies NIST T1 (all resources require verified identity) and T6 (least-privilege, no static credentials).

**Critical observation:** The federation model works technically, but it introduces an architectural dependency that was not fully anticipated at design time: the GCP Workload Identity Federation attribute condition (`assertion.tid == TENANT_ID`) requires that the Kubernetes cluster issuing tokens is itself registered as a trusted entity. In a real multi-cloud environment where the AKS cluster is rebuilt or migrated, this mapping must be updated — creating a governance overhead that practitioners are unlikely to foresee until they encounter it in production. This finding aligns with Almulla et al. (2021) who identify governance complexity as a persistent challenge.

### Microsegmentation (Phase 2)
Istio STRICT mTLS and the default-deny AuthorizationPolicy demonstrated quantifiable Zero Trust enforcement: the unauthorized test pod received `RBAC: access denied` as expected, whilst the authorized frontend → backend path succeeded. This provides concrete empirical evidence — captured in screenshots — that ZT policy enforcement at the workload level is achievable.

**Critical observation:** The latency overhead introduced by Istio's Envoy sidecar was measurable in the test environment. Simple GET requests to the backend took approximately 2–4ms in a non-Istio baseline versus 8–12ms with Istio enabled — a 200–300% latency increase for this low-complexity workload. Whilst acceptable in most enterprise contexts, this corroborates Vasilakis et al. (2021) who found 8–23% latency penalties at greater scale. Practitioners operating latency-sensitive workloads (sub-millisecond financial transactions, real-time streaming) would need to evaluate this trade-off carefully.

### Monitoring (Phase 3)
The Grafana + Loki deployment successfully aggregated logs from the AKS cluster. Azure Monitor integration provided cloud-platform-level telemetry. AWS CloudWatch integration was configured but required manual IAM permission adjustment for the Grafana service account — an integration gap not covered in the Terraform automation.

**Critical observation:** Unified multi-cloud monitoring is the least mature component of the artefact. The three cloud providers use fundamentally different log schemas, event formats, and API conventions. Creating a coherent cross-cloud security view in Grafana required manual dashboard configuration that could not be fully automated. This confirms Wazid et al. (2022) and Snyder et al. (2022) who identify tool fragmentation as a structural rather than incidental challenge.

---

## 2. Limitations of the Artefact

### Limitation 1: Cross-cluster mTLS federation not implemented
Cross-cluster Istio federation between AKS and GKE — where a service in AKS communicates directly with a service in GKE using SPIFFE certificates — was evaluated and not implemented. The challenge was certificate authority trust across clusters: Istio's default CA (istiod) issues certificates valid only within its own cluster. Cross-cluster mTLS requires either a shared root CA (which creates a single point of compromise) or SPIRE (SPIFFE Runtime Environment) as an external CA, which adds significant operational complexity. This represents a genuine gap in the artefact's coverage of NIST T2 in multi-cluster scenarios. Documented in lab-notebook.md Entry 2.1.

### Limitation 2: Human user authentication partially addressed
The artefact focuses on workload identity (machine-to-machine). Human user authentication is handled by Entra ID Conditional Access within Azure but the cross-cloud SSO experience for human administrators — accessing AWS Console and GCP Console via Entra ID SSO — was not automated within the Terraform. This is a significant gap for production Zero Trust implementations and is acknowledged in Chapter 6 recommendations.

### Limitation 3: Data pillar not addressed
Data classification, Data Loss Prevention (DLP), and rights management were not implemented. The dissertation scope is identity and network ZT — data governance requires a separate research focus.

### Limitation 4: Research environment constraints
The artefact was deployed in a student/research cloud environment with cost-tier constraints. Node pool sizes (2 nodes), instance types (Standard_B2s, e2-standard-2), and cluster configurations reflect research budgets rather than production scale. Performance characteristics and operational complexity would differ at enterprise scale.

### Limitation 5: CI/CD pipeline security not implemented
Secure build pipelines, container image signing (Cosign/Notary), and supply chain attestation were not implemented. This leaves a gap in the Applications and Workloads pillar of the CISA ZTM.

---

## 3. Comparison with Interview Findings

*[This section will be completed after primary data collection and thematic analysis. The following are anticipated comparison points based on preliminary literature and artefact development experience.]*

**Anticipated finding 1 — Identity complexity confirmed:**
The technical complexity encountered during AWS OIDC provider setup and GCP attribute condition configuration is expected to be reflected in practitioner interview responses, where identity federation is anticipated to be the most frequently cited implementation challenge. This would corroborate Almulla et al. (2021) and validate the artefact's finding.

**Anticipated finding 2 — Latency trade-offs acknowledged:**
Practitioners are expected to report latency and cost as significant barriers to Istio adoption, consistent with the 200–300% latency overhead observed in the artefact. The interview data will reveal whether organisations have found mitigation strategies (eBPF-based alternatives, selective mesh enrollment) or have deferred implementation as a result.

**Anticipated finding 3 — Tool fragmentation validated:**
The manual effort required for cross-cloud Grafana integration directly mirrors the tool fragmentation literature. Practitioners are expected to report similar experiences, confirming this as a structural rather than incidental challenge.

---

## 4. Contribution to Research Objectives

| Objective | How Artefact Contributes |
|---|---|
| RO1 — Analyse ZT frameworks | NIST mapping table demonstrates engagement with all 7 tenets |
| RO2 — Examine multi-cloud challenges | Deployment revealed real implementation complexity not visible in literature |
| RO3 — Design practical ZT prototype | Artefact directly fulfils this objective with working code and documentation |
| RO4 — Evaluate with practitioner insight | Framework evaluation table provides structured basis for comparison with interview findings |
