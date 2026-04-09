# =============================================================================
# OPA Rego Policy — Block Privileged Containers
#
# NIST SP 800-207 Tenet T6: Least-privilege access enforced
# NIST SP 800-207 Tenet T4: Dynamic policy evaluated at admission time
#
# This policy is enforced by OPA Gatekeeper at the Kubernetes API server level.
# Any pod spec requesting privileged: true is rejected before it reaches a node.
# This prevents container escapes that would violate workload isolation.
# =============================================================================

package kubernetes.admission

# Deny privileged containers
deny[msg] {
  input.request.kind.kind == "Pod"
  container := input.request.object.spec.containers[_]
  container.securityContext.privileged == true
  msg := sprintf(
    "DENIED (ZT Policy): Container '%v' in Pod '%v' requests privileged mode. Zero Trust policy requires least-privilege — remove securityContext.privileged or set to false.",
    [container.name, input.request.object.metadata.name]
  )
}

# Deny privileged init containers
deny[msg] {
  input.request.kind.kind == "Pod"
  container := input.request.object.spec.initContainers[_]
  container.securityContext.privileged == true
  msg := sprintf(
    "DENIED (ZT Policy): Init container '%v' requests privileged mode. Zero Trust policy prohibits this.",
    [container.name]
  )
}

# Deny hostPID — prevents container from seeing host processes
deny[msg] {
  input.request.kind.kind == "Pod"
  input.request.object.spec.hostPID == true
  msg := sprintf(
    "DENIED (ZT Policy): Pod '%v' requests hostPID. This violates workload isolation principles.",
    [input.request.object.metadata.name]
  )
}

# Deny hostNetwork — prevents bypassing network policies
deny[msg] {
  input.request.kind.kind == "Pod"
  input.request.object.spec.hostNetwork == true
  msg := sprintf(
    "DENIED (ZT Policy): Pod '%v' requests hostNetwork. This bypasses Istio mTLS enforcement.",
    [input.request.object.metadata.name]
  )
}

# Require runAsNonRoot — NIST T6: no root processes in containers
deny[msg] {
  input.request.kind.kind == "Pod"
  container := input.request.object.spec.containers[_]
  not container.securityContext.runAsNonRoot
  not input.request.object.metadata.annotations["zt-policy/allow-root"]
  msg := sprintf(
    "DENIED (ZT Policy): Container '%v' does not set runAsNonRoot: true. Zero Trust policy requires non-root workloads.",
    [container.name]
  )
}
