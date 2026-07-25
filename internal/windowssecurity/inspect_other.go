//go:build !windows

package windowssecurity

import (
	"errors"
	"os"
)

func CurrentActorSID() (string, error) {
	return "", errors.New("Windows security descriptors are unavailable on this platform")
}

func InspectPrivateFile(*os.File, ObjectKind) error {
	return errors.New("Windows security descriptors are unavailable on this platform")
}

func InspectPrivateFileForActor(*os.File, ObjectKind, string) error {
	return errors.New("Windows security descriptors are unavailable on this platform")
}

func InspectPrivateFileSingleLink(*os.File, ObjectKind) error {
	return errors.New("Windows security descriptors are unavailable on this platform")
}

func InspectPrivateChildFile(*os.File) error {
	return errors.New("Windows security descriptors are unavailable on this platform")
}

func InspectPrivateChildFileForActor(*os.File, string) error {
	return errors.New("Windows security descriptors are unavailable on this platform")
}

func InspectPrivateManagedFileForActor(*os.File, string) error {
	return errors.New("Windows security descriptors are unavailable on this platform")
}

func InspectPrivateManagedFileSingleLinkForActor(*os.File, string) error {
	return errors.New("Windows security descriptors are unavailable on this platform")
}

func InspectPrivateChildDirectory(*os.File) error {
	return errors.New("Windows security descriptors are unavailable on this platform")
}

func InspectPrivateChildDirectoryForActor(*os.File, string) error {
	return errors.New("Windows security descriptors are unavailable on this platform")
}

func InspectPrivateManagedDirectoryForActor(*os.File, string) error {
	return errors.New("Windows security descriptors are unavailable on this platform")
}

func InspectPrivatePath(string, os.FileInfo, ObjectKind) error {
	return errors.New("Windows security descriptors are unavailable on this platform")
}

func InspectPrivatePathForActor(string, os.FileInfo, ObjectKind, string) error {
	return errors.New("Windows security descriptors are unavailable on this platform")
}

func ProtectPrivatePath(string, os.FileInfo, ObjectKind, string) error {
	return errors.New("Windows security descriptors are unavailable on this platform")
}
