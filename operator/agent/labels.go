package agent

// labelsForManaged returns the generic Tetragon labels plus ManagedBy label.
func labelsForManaged() map[string]string {
	return map[string]string{
		"app.kubernetes.io/instance":   DaemonSetName,
		"app.kubernetes.io/name":       DaemonSetName,
		"app.kubernetes.io/managed-by": "tetragon-operator",
	}
}
