package agent

// labelsForManaged returns the generic Tetragon labels plus ManagedBy label.
func labelsForManaged(name string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/instance":   name,
		"app.kubernetes.io/name":       name,
		"app.kubernetes.io/managed-by": "tetragon-operator",
	}
}
