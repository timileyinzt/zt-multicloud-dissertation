# Deployment Guide — Zero Trust Multi-Cloud Artefact

**W24065387 — Timileyin Badiru**  
**Estimated deployment time: 45–60 minutes** (excluding cloud provisioning time)

---

## Prerequisites

Verify all tools are installed before starting:

```bash
terraform version      # >= 1.6.0
az version             # Azure CLI
aws --version          # AWS CLI v2
gcloud version         # Google Cloud SDK
kubectl version        # >= 1.28
istioctl version       # >= 1.20
helm version           # >= 3.12
```

---

## Step 1 — Environment Variables

Set these in your shell before running any Terraform commands. Never hardcode credentials.

```bash
# Azure
export ARM_SUBSCRIPTION_ID="<your-azure-subscription-id>"
export ARM_TENANT_ID="<your-azure-tenant-id>"
export TF_VAR_azure_tenant_id="<your-azure-tenant-id>"

# AWS
export AWS_ACCESS_KEY_ID="<your-aws-access-key>"
export AWS_SECRET_ACCESS_KEY="<your-aws-secret-key>"
export TF_VAR_aws_account_id="<your-aws-account-id>"

# GCP
export GOOGLE_APPLICATION_CREDENTIALS="<path-to-service-account-key.json>"
export TF_VAR_gcp_project_id="<your-gcp-project-id>"

# Grafana
export TF_VAR_grafana_admin_password="<choose-a-strong-password>"
```

---

## Step 2 — Phase 1: Identity Federation

This is the most important phase — it establishes the Zero Trust identity plane across all three clouds.

```bash
cd terraform/modules/identity

terraform init
terraform plan   # Review what will be created
terraform apply  # Confirm with 'yes'
```

**Expected outputs after apply:**
```
aws_oidc_provider_arn     = "arn:aws:iam::XXXX:oidc-provider/login.microsoftonline.com/..."
aws_federated_role_arn    = "arn:aws:iam::XXXX:role/zt-federated-workload-role"
gcp_pool_name             = "projects/PROJECT/locations/global/workloadIdentityPools/zt-dissertation-pool"
gcp_workload_sa_email     = "zt-federated-workload@PROJECT.iam.gserviceaccount.com"
gcp_wif_audience          = "//iam.googleapis.com/projects/..."
```

**Screenshot to take:** The full `terraform apply` output showing all resources created.

---

## Step 3 — Phase 2: Cloud Infrastructure

Deploy in this order: Azure first (generates OIDC issuer URL needed by others), then AWS and GCP in parallel.

```bash
# Azure
cd ../../azure
terraform init && terraform apply

# Note the AKS OIDC issuer URL from the output:
# aks_oidc_issuer_url = "https://uksouth.oic.prod-aks.azure.com/TENANT/CLUSTER/"

# AWS (can run in parallel with GCP)
cd ../aws
terraform init && terraform apply

# GCP
cd ../gcp
terraform init && terraform apply
```

**Screenshot to take:** Azure portal showing AKS cluster with Istio add-on enabled.

---

## Step 4 — Configure kubectl

```bash
# Get AKS credentials
az aks get-credentials \
  --resource-group zt-dissertation-rg \
  --name zt-aks-cluster \
  --overwrite-existing

# Verify cluster access
kubectl get nodes
kubectl get pods -n istio-system
```

**Expected:** 2 nodes in Ready state, Istio control plane pods running.

---

## Step 5 — Install Istio (if not using Azure managed ASM)

If you chose manual Istio installation instead of the Azure managed add-on:

```bash
# Install using the ZT operator profile
istioctl install -f kubernetes/istio/install/istio-operator.yaml

# Verify installation
istioctl verify-install
kubectl get pods -n istio-system
```

**Expected output:**
```
NAME                                    READY   STATUS    RESTARTS
istiod-XXXX                             1/1     Running   0
istio-ingressgateway-XXXX               1/1     Running   0
```

---

## Step 6 — Apply Zero Trust Policies

```bash
# Apply PeerAuthentication — enforces STRICT mTLS mesh-wide
kubectl apply -f kubernetes/istio/policies/peer-auth-strict.yaml

# Verify mTLS is STRICT
kubectl get peerauthentication -A

# Apply AuthorizationPolicies — default deny + explicit allows
kubectl apply -f kubernetes/istio/policies/authorization-policies.yaml

# Verify policies
kubectl get authorizationpolicy -n zt-demo
```

**Screenshot to take:** Output of `kubectl get peerauthentication -A` showing STRICT mode.

---

## Step 7 — Install OPA Gatekeeper

```bash
# Install Gatekeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml

# Wait for Gatekeeper to be ready
kubectl wait --for=condition=ready pod -l control-plane=controller-manager -n gatekeeper-system --timeout=90s

# Apply constraint templates and constraints
kubectl apply -f kubernetes/opa/deployment.yaml

# Verify constraints
kubectl get constraints
```

---

## Step 8 — Deploy Demo Application

```bash
# Create namespace (with Istio injection label)
kubectl apply -f kubernetes/demo-app/demo-workloads.yaml

# Verify pods have 2/2 containers (app + Istio sidecar)
kubectl get pods -n zt-demo
```

**Expected output:**
```
NAME                             READY   STATUS    RESTARTS
zt-backend-XXXX                  2/2     Running   0   ← 2/2 = app + Envoy sidecar
zt-frontend-XXXX                 2/2     Running   0   ← 2/2 = app + Envoy sidecar
zt-test-unauthorized             2/2     Running   0
```

**Screenshot to take:** `kubectl get pods -n zt-demo` showing 2/2 for all pods.

---

## Step 9 — Demonstrate ZT Enforcement (Viva Evidence)

### Test 1: Authorised traffic (frontend → backend) — should SUCCEED
```bash
FRONTEND_POD=$(kubectl get pod -n zt-demo -l app=zt-frontend -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n zt-demo $FRONTEND_POD -c frontend -- \
  curl -s http://zt-backend:8080/api/test
```
**Expected:** `ZT Backend Response: Identity verified, request authorised`

### Test 2: Unauthorised traffic (test pod → backend) — should FAIL
```bash
kubectl exec -n zt-demo zt-test-unauthorized -c curl -- \
  curl -s --max-time 5 http://zt-backend:8080/api/test
```
**Expected:** `RBAC: access denied` (Istio 403)

### Test 3: OPA Gatekeeper — privileged container rejected
```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-privileged
  namespace: zt-demo
  labels:
    app: test
    owner: test
    version: v1
spec:
  containers:
  - name: test
    image: nginx
    securityContext:
      privileged: true
EOF
```
**Expected:** `Error from server: admission webhook ... denied: ZT Policy DENIED: Container 'test' requests privileged mode.`

**Screenshot to take:** All three test outputs — one success, two denials.

---

## Step 10 — Deploy Monitoring

```bash
cd terraform/modules/monitoring
terraform init && terraform apply
```

Access Grafana:
```bash
kubectl get svc -n monitoring grafana
# Get the external IP, open in browser: http://EXTERNAL_IP:80
```

**Screenshot to take:** Grafana dashboard showing Istio traffic graph with mTLS badges on all connections.

---

## Teardown (After Viva)

```bash
# Remove Kubernetes resources
kubectl delete namespace zt-demo
kubectl delete namespace gatekeeper-system
istioctl uninstall --purge

# Destroy cloud infrastructure (in reverse order)
cd terraform/modules/monitoring && terraform destroy
cd terraform/gcp && terraform destroy
cd terraform/aws && terraform destroy
cd terraform/azure && terraform destroy
cd terraform/modules/identity && terraform destroy
```

---

## Troubleshooting

| Issue | Likely cause | Resolution |
|---|---|---|
| Pods stuck at 1/2 READY | Istio sidecar not injecting | Check namespace has `istio-injection: enabled` label |
| mTLS connection failures | PeerAuthentication too strict | Check `istioctl proxy-config listeners` on the failing pod |
| OPA webhook timeout | Gatekeeper not ready | Wait 60s after Gatekeeper install before applying constraints |
| Terraform OIDC thumbprint error | Certificate changed | Re-run `terraform apply` — tls_certificate data source refreshes automatically |
| GCP WIF 403 | Attribute condition mismatch | Verify tenant ID in `attribute_condition` matches `ARM_TENANT_ID` |
