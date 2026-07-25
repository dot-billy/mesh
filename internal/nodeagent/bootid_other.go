//go:build !linux && !darwin

package nodeagent

func systemBootID() (string, bool) { return "", false }
