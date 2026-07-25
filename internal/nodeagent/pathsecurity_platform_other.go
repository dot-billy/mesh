//go:build !darwin

package nodeagent

func validatePlatformPathSecurity(string) error { return nil }
