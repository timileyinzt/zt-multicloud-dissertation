# Lab Notebook — Zero Trust Multi-Cloud Artefact

**Researcher:** Timileyin Badiru (W24065387)

---

## Entry 1.1 — Choice of Central Identity Provider
**Decision:** Azure Entra ID selected as central IdP.
**Alternatives rejected:**
- Okta standalone: introduces third-party single point of failure (Almulla et al., 2021)
- HashiCorp Vault: optimised for secrets, not primary workload authentication
- AWS IAM Identity Centre: creates AWS vendor lock-in for identity plane
**Rationale:** Active Azure subscription available; Entra ID supports OIDC federation natively to both AWS and GCP.
**Limitation:** Organisations without Azure cannot directly reuse this model — acknowledged in evaluation.

## Entry 1.2 — AWS Federation Method
**Decision:** OIDC federation (not SAML).
**Rationale:** SAML is session-based, unsuitable for machine-to-machine ZT verification. OIDC tokens support continuous per-request verification aligned with NIST T3.

## Entry 2.1 — Service Mesh Selection
**Decision:** Istio selected over Linkerd and Cilium.
**Linkerd rejected:** Certificate authority does not support cross-cluster federation at required level; lacks expressive AuthorizationPolicy.
**Cilium rejected:** Requires kernel >= 5.4 with specific node config across AKS and GKE — too complex for dissertation timeline. Flagged in recommendations as superior production option.
**NetworkPolicies only rejected:** L3/L4 only — cannot verify workload identity. Fails NIST T2.

## Entry 2.2 — Istio mTLS Mode
**Decision:** STRICT global, not PERMISSIVE or per-namespace.
**Rationale:** PERMISSIVE allows plaintext — defeats ZT principle. Global STRICT from outset maximises NIST T2 compliance.

## Entry 3.1 — Monitoring Stack
**Decision:** Grafana + Loki over Sentinel-only or ELK.
**Sentinel rejected:** Azure-native, unsuitable as neutral three-cloud aggregation layer.
**ELK rejected:** Elasticsearch resource requirements cost-prohibitive on student-tier cloud.
