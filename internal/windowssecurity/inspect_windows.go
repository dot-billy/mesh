//go:build windows

package windowssecurity

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var reOpenFileProcedure = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReOpenFile")

// CurrentActorSID returns the user SID of the process token. A Windows service
// running as LocalSystem therefore binds state to LocalSystem; a deliberately
// configured service account binds state to that account instead.
func CurrentActorSID() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return "", fmt.Errorf("read Windows process identity SID: %w", err)
	}
	return user.User.Sid.String(), nil
}

// InspectPrivateFile authenticates the type, reparse status, owner, and exact
// protected DACL through the already-open file handle.
func InspectPrivateFile(file *os.File, kind ObjectKind) error {
	actorSID, err := CurrentActorSID()
	if err != nil {
		return err
	}
	return inspectPrivateFileForActor(file, kind, actorSID, false)
}

func InspectPrivateFileForActor(file *os.File, kind ObjectKind, actorSID string) error {
	return inspectPrivateFileForActor(file, kind, actorSID, false)
}

func InspectPrivateFileSingleLink(file *os.File, kind ObjectKind) error {
	actorSID, err := CurrentActorSID()
	if err != nil {
		return err
	}
	return inspectPrivateFileForActor(file, kind, actorSID, true)
}

func InspectPrivateFileSingleLinkForActor(file *os.File, kind ObjectKind, actorSID string) error {
	if !canonicalSID(actorSID) {
		return errors.New("Windows service identity SID is not canonical")
	}
	return inspectPrivateFileForActor(file, kind, actorSID, true)
}

func InspectPrivateChildFile(file *os.File) error {
	actorSID, err := CurrentActorSID()
	if err != nil {
		return err
	}
	return inspectPrivateFile(file, RegularFile, actorSID, false, true)
}

func InspectPrivateChildFileForActor(file *os.File, actorSID string) error {
	return inspectPrivateFile(file, RegularFile, actorSID, false, true)
}

func InspectPrivateManagedFileForActor(file *os.File, actorSID string) error {
	return inspectPrivateManaged(file, RegularFile, actorSID, false)
}

// InspectPrivateManagedFileSingleLinkForActor accepts either the canonical
// explicit managed-file DACL or the exact DACL inherited from an authenticated
// managed parent, while also rejecting external hard-link aliases.
func InspectPrivateManagedFileSingleLinkForActor(file *os.File, actorSID string) error {
	return inspectPrivateManaged(file, RegularFile, actorSID, true)
}

func InspectPrivateChildDirectory(file *os.File) error {
	actorSID, err := CurrentActorSID()
	if err != nil {
		return err
	}
	return inspectPrivateFile(file, Directory, actorSID, false, true)
}

func InspectPrivateChildDirectoryForActor(file *os.File, actorSID string) error {
	return inspectPrivateFile(file, Directory, actorSID, false, true)
}

func InspectPrivateManagedDirectoryForActor(file *os.File, actorSID string) error {
	return inspectPrivateManaged(file, Directory, actorSID, false)
}

func inspectPrivateManaged(file *os.File, kind ObjectKind, actorSID string, requireSingleLink bool) error {
	if err := inspectPrivateFile(file, kind, actorSID, requireSingleLink, false); err == nil {
		return nil
	}
	return inspectPrivateFile(file, kind, actorSID, requireSingleLink, true)
}

func InspectPrivatePath(path string, expected os.FileInfo, kind ObjectKind) error {
	return openSensitivePath(path, expected, kind, false, "")
}

func InspectPrivatePathForActor(path string, expected os.FileInfo, kind ObjectKind, actorSID string) error {
	if !canonicalSID(actorSID) {
		return errors.New("Windows service identity SID is not canonical")
	}
	return openSensitivePath(path, expected, kind, false, actorSID)
}

// ProtectPrivatePath replaces the DACL and owner of one already-created,
// no-follow object with the canonical Mesh service policy, then verifies the
// resulting descriptor through the same handle. The caller must possess
// WRITE_DAC and WRITE_OWNER; installers should fail rather than weaken the
// requested service identity when those rights are unavailable.
func ProtectPrivatePath(path string, expected os.FileInfo, kind ObjectKind, actorSID string) error {
	if !canonicalSID(actorSID) {
		return errors.New("Windows service identity SID is not canonical")
	}
	return openSensitivePath(path, expected, kind, true, actorSID)
}

// ProtectPrivateFileForActor applies the canonical owner and protected DACL
// through an already-open, no-follow handle. This is the preferred installer
// primitive when the caller resolved the object relative to an authenticated
// directory handle.
func ProtectPrivateFileForActor(file *os.File, kind ObjectKind, actorSID string) error {
	if file == nil {
		return errors.New("Windows object handle is required")
	}
	if !canonicalSID(actorSID) {
		return errors.New("Windows service identity SID is not canonical")
	}
	connection, err := file.SyscallConn()
	if err != nil {
		return fmt.Errorf("access Windows object handle: %w", err)
	}
	var protectErr error
	controlErr := connection.Control(func(raw uintptr) {
		original := windows.Handle(raw)
		if err := validatePrivateHandleIdentity(original, kind, false); err != nil {
			protectErr = err
			return
		}
		handle, err := reopenPrivateSecurityHandle(original, kind)
		if err != nil {
			protectErr = err
			return
		}
		defer windows.CloseHandle(handle)
		if err := validatePrivateHandleIdentity(handle, kind, false); err != nil {
			protectErr = err
			return
		}
		protectErr = protectPrivateHandle(handle, kind, actorSID)
	})
	runtime.KeepAlive(file)
	if controlErr != nil {
		return fmt.Errorf("protect Windows object handle: %w", controlErr)
	}
	if protectErr != nil {
		return protectErr
	}
	return InspectPrivateFileForActor(file, kind, actorSID)
}

// ReOpenFile preserves the already-resolved kernel file object while adding
// only the access rights required to set its owner and DACL. Go's ordinary
// create/open handles intentionally do not request WRITE_DAC or WRITE_OWNER.
func reopenPrivateSecurityHandle(original windows.Handle, kind ObjectKind) (windows.Handle, error) {
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if kind == Directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	} else if kind != RegularFile {
		return 0, errors.New("Windows object kind is invalid")
	}
	desired := uint32(windows.READ_CONTROL | windows.WRITE_DAC | windows.WRITE_OWNER | windows.FILE_READ_ATTRIBUTES)
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	result, _, callErr := reOpenFileProcedure.Call(uintptr(original), uintptr(desired), uintptr(share), uintptr(flags))
	handle := windows.Handle(result)
	if handle == windows.InvalidHandle {
		if errno, ok := callErr.(syscall.Errno); ok && errno != 0 {
			return 0, fmt.Errorf("reopen Windows object for descriptor mutation: %w", errno)
		}
		return 0, errors.New("reopen Windows object for descriptor mutation")
	}
	return handle, nil
}

func openSensitivePath(path string, expected os.FileInfo, kind ObjectKind, mutate bool, actorSID string) error {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("encode Windows sensitive path: %w", err)
	}
	desiredAccess := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES)
	if mutate {
		desiredAccess |= windows.WRITE_DAC | windows.WRITE_OWNER
	}
	handle, err := windows.CreateFile(
		pathPointer,
		desiredAccess,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return fmt.Errorf("open Windows sensitive path without following reparses: %w", err)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return errors.New("wrap Windows sensitive path handle")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || expected == nil || !os.SameFile(expected, opened) {
		return errors.New("Windows sensitive path changed while opening")
	}
	if mutate {
		if err := protectPrivateHandle(handle, kind, actorSID); err != nil {
			return err
		}
		return InspectPrivateFileForActor(file, kind, actorSID)
	}
	if actorSID != "" {
		return InspectPrivateFileForActor(file, kind, actorSID)
	}
	return InspectPrivateFile(file, kind)
}

func protectPrivateHandle(handle windows.Handle, kind ObjectKind, actorSID string) error {
	actor, err := windows.StringToSid(actorSID)
	if err != nil {
		return fmt.Errorf("parse Windows service identity SID: %w", err)
	}
	system, err := windows.StringToSid(LocalSystemSID)
	if err != nil {
		return fmt.Errorf("parse LocalSystem SID: %w", err)
	}
	administrators, err := windows.StringToSid(AdministratorsSID)
	if err != nil {
		return fmt.Errorf("parse Administrators SID: %w", err)
	}
	unique := []*windows.SID{actor, system, administrators}
	seen := make(map[string]struct{}, len(unique))
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(unique))
	inheritance := uint32(windows.NO_INHERITANCE)
	if kind == Directory {
		inheritance = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	} else if kind != RegularFile {
		return errors.New("Windows object kind is invalid")
	}
	for _, sid := range unique {
		text := sid.String()
		if _, duplicate := seen[text]; duplicate {
			continue
		}
		seen[text] = struct{}{}
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("build canonical Windows DACL: %w", err)
	}
	if err := windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		actor,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("apply canonical Windows owner and protected DACL: %w", err)
	}
	runtime.KeepAlive(entries)
	runtime.KeepAlive(unique)
	return nil
}

func inspectPrivateFileForActor(file *os.File, kind ObjectKind, actorSID string, requireSingleLink bool) error {
	return inspectPrivateFile(file, kind, actorSID, requireSingleLink, false)
}

func inspectPrivateFile(file *os.File, kind ObjectKind, actorSID string, requireSingleLink, inheritedChild bool) error {
	if file == nil {
		return errors.New("Windows object handle is required")
	}
	connection, err := file.SyscallConn()
	if err != nil {
		return fmt.Errorf("access Windows object handle: %w", err)
	}
	var inspectErr error
	controlErr := connection.Control(func(raw uintptr) {
		handle := windows.Handle(raw)
		if err := validatePrivateHandleIdentity(handle, kind, requireSingleLink); err != nil {
			inspectErr = err
			return
		}
		descriptor, err := descriptorForHandle(handle)
		if err != nil {
			inspectErr = err
			return
		}
		if inheritedChild {
			inspectErr = ValidatePrivateChildDescriptor(descriptor, actorSID, kind)
		} else {
			inspectErr = ValidatePrivateDescriptor(descriptor, actorSID, kind)
		}
	})
	runtime.KeepAlive(file)
	if controlErr != nil {
		return fmt.Errorf("inspect Windows object handle: %w", controlErr)
	}
	return inspectErr
}

func validatePrivateHandleIdentity(handle windows.Handle, kind ObjectKind, requireSingleLink bool) error {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return fmt.Errorf("inspect Windows object identity: %w", err)
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("Windows sensitive object cannot be a reparse point")
	}
	if requireSingleLink && information.NumberOfLinks != 1 {
		return fmt.Errorf("Windows sensitive file has %d hard links, want exactly one", information.NumberOfLinks)
	}
	isDirectory := information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if kind == Directory && !isDirectory || kind == RegularFile && isDirectory {
		return errors.New("Windows sensitive object type does not match its policy")
	}
	if kind != Directory && kind != RegularFile {
		return errors.New("Windows object kind is invalid")
	}
	return nil
}

func descriptorForHandle(handle windows.Handle) (Descriptor, error) {
	return descriptorForObjectHandle(handle, windows.SE_FILE_OBJECT)
}

func descriptorForObjectHandle(handle windows.Handle, objectType windows.SE_OBJECT_TYPE) (Descriptor, error) {
	securityDescriptor, err := windows.GetSecurityInfo(handle, objectType, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return Descriptor{}, fmt.Errorf("read Windows security descriptor: %w", err)
	}
	if securityDescriptor == nil {
		return Descriptor{}, errors.New("Windows object has no security descriptor")
	}
	owner, ownerDefaulted, err := securityDescriptor.Owner()
	if err != nil || owner == nil || !owner.IsValid() || ownerDefaulted {
		return Descriptor{}, errors.New("Windows object owner SID is absent, invalid, or defaulted")
	}
	control, _, err := securityDescriptor.Control()
	if err != nil {
		return Descriptor{}, fmt.Errorf("read Windows security descriptor control: %w", err)
	}
	result := Descriptor{
		OwnerSID:      owner.String(),
		DACLPresent:   control&windows.SE_DACL_PRESENT != 0,
		DACLProtected: control&windows.SE_DACL_PROTECTED != 0,
	}
	dacl, defaulted, err := securityDescriptor.DACL()
	if err != nil {
		if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
			return result, nil
		}
		return Descriptor{}, fmt.Errorf("read Windows object DACL: %w", err)
	}
	result.DACLDefaulted = defaulted
	if dacl == nil {
		result.DACLNull = true
		return result, nil
	}
	result.Entries = make([]ACE, 0, dacl.AceCount)
	for index := uint16(0); index < dacl.AceCount; index++ {
		var native *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &native); err != nil || native == nil {
			return Descriptor{}, fmt.Errorf("read Windows DACL entry %d: %w", index, err)
		}
		entry := ACE{Type: native.Header.AceType, Flags: native.Header.AceFlags, Mask: uint32(native.Mask)}
		if native.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			minimum := uintptr(unsafe.Offsetof(native.SidStart)) + 8
			if uintptr(native.Header.AceSize) < minimum {
				return Descriptor{}, fmt.Errorf("Windows DACL entry %d is truncated", index)
			}
			sid := (*windows.SID)(unsafe.Pointer(&native.SidStart))
			if !sid.IsValid() || uintptr(unsafe.Offsetof(native.SidStart))+uintptr(sid.Len()) > uintptr(native.Header.AceSize) {
				return Descriptor{}, fmt.Errorf("Windows DACL entry %d has an invalid SID", index)
			}
			entry.SID = sid.String()
		}
		result.Entries = append(result.Entries, entry)
	}
	runtime.KeepAlive(securityDescriptor)
	return result, nil
}
