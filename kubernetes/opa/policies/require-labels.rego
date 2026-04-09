# =============================================================================
# OPA Rego Policy — Require ZT Labels on All Pods
#
# NIST SP 800-207 Tenet T5: Continuous monitoring requires identifiable workloads
#
# Every pod deployed in the zt-demo namespace must carry:
#   - app: identifies the workload in Istio traffic graphs and Grafana dashboards
#   - owner: identifies the team/person responsible — essential for incident response
#   - version: enables canary/rollback decisions, correlates logs to deployments
#
# Without these labels, monitoring tools cannot correlate logs to workloads,
# violating the continuous monitoring requirement of NIST T5.
# =============================================================================

package kubernetes.labels

# Main violation rule — triggered when required labels are missing
deny[msg] {
  input.request.kind.kind == "Pod"

  # Build sets of provided and required labels
  provided_labels := {label | input.request.object.metadata.labels[label]}

  required_labels := {"app", "owner", "version"}

  # Find which required labels are absent
  missing_labels := required_labels - provided_labels

  # Trigger violation if any required label is missing
  count(missing_labels) > 0

  msg := sprintf(
    "DENIED (ZT Policy — NIST T5): Pod '%v' is missing required labels: %v. All pods must be labelled for monitoring and audit trail.",
    [
      input.request.object.metadata.name,
      missing_labels
    ]
  )
}

# Additional check: app label must not be 'undefined' or empty
deny[msg] {
  input.request.kind.kind == "Pod"
  app_label := input.request.object.metadata.labels.app
  app_label == ""
  msg := "DENIED (ZT Policy): Label 'app' must not be empty."
}

# Warn (not deny) if owner label does not match known team pattern
# This is a warn-only rule — use enforcementAction: warn in constraint
warn[msg] {
  input.request.kind.kind == "Pod"
  owner := input.request.object.metadata.labels.owner
  not regex.match(`^[a-z0-9-]+$`, owner)
  msg := sprintf(
    "WARNING (ZT Policy): Owner label '%v' does not match expected pattern [a-z0-9-]. Consider standardising.",
    [owner]
  )
}
