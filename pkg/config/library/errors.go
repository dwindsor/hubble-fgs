package library

// ConfigNotFoundError represents an error when a configuration is not found
type ConfigNotFoundError struct{}

// Error implements the error interface
func (e *ConfigNotFoundError) Error() string {
	return "config not found"
}

// IsConfigNotFound checks if an error is a ConfigNotFoundError
func IsConfigNotFound(err error) bool {
	_, ok := err.(*ConfigNotFoundError)
	return ok
}
