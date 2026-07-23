//go:build darwin

package nodeagent

import "syscall"

// systemBootID derives a stable per-boot identity from the Darwin kernel's
// timeval-valued kern.boottime sysctl. syscall.Sysctl removes one trailing NUL
// byte even for binary values; parseDarwinBootTime accepts only that exact
// truncation or the complete native timeval representation.
func systemBootID() (string, bool) {
	raw, err := syscall.Sysctl("kern.boottime")
	if err != nil {
		return "", false
	}
	return parseDarwinBootTime([]byte(raw))
}
