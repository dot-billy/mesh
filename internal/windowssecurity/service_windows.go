//go:build windows

package windowssecurity

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

// InspectPrivateServiceObject authenticates the owner and exact protected DACL
// of an SCM service object through its already-open service handle.
func InspectPrivateServiceObject(handle windows.Handle) error {
	descriptor, err := descriptorForObjectHandle(handle, windows.SE_SERVICE)
	if err != nil {
		return err
	}
	return ValidatePrivateServiceDescriptor(descriptor)
}

// ProtectPrivateServiceObject replaces the owner and DACL of an SCM service
// object with the canonical Mesh policy and verifies the result through the
// same handle. The caller must open the service with WRITE_DAC, WRITE_OWNER,
// and READ_CONTROL rights.
func ProtectPrivateServiceObject(handle windows.Handle) error {
	system, err := windows.StringToSid(LocalSystemSID)
	if err != nil {
		return fmt.Errorf("parse LocalSystem SID: %w", err)
	}
	administrators, err := windows.StringToSid(AdministratorsSID)
	if err != nil {
		return fmt.Errorf("parse Administrators SID: %w", err)
	}
	trustees := []*windows.SID{system, administrators}
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(trustees))
	for _, sid := range trustees {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.SERVICE_ALL_ACCESS,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("build canonical Windows service DACL: %w", err)
	}
	if err := windows.SetSecurityInfo(
		handle,
		windows.SE_SERVICE,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		administrators,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("apply canonical Windows service owner and DACL: %w", err)
	}
	runtime.KeepAlive(entries)
	runtime.KeepAlive(trustees)
	return InspectPrivateServiceObject(handle)
}
