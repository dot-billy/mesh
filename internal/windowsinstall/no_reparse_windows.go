//go:build windows

package windowsinstall

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// openNoReparseDirectory walks a clean drive-letter path one component at a
// time. Each component is opened relative to the retained parent handle with
// FILE_OPEN_REPARSE_POINT and OBJ_DONT_REPARSE, then authenticated as a real
// directory before the walk continues.
func openNoReparseDirectory(path string) (*os.File, error) {
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("Windows directory walk requires a clean absolute drive-letter path")
	}
	volumeRoot := volume + `\`
	rootPointer, err := windows.UTF16PtrFromString(volumeRoot)
	if err != nil {
		return nil, fmt.Errorf("encode Windows volume root: %w", err)
	}
	handle, err := windows.CreateFile(
		rootPointer,
		windows.FILE_READ_ATTRIBUTES|windows.FILE_TRAVERSE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("anchor Windows volume root: %w", err)
	}
	var volumeInformation windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &volumeInformation); err != nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("inspect Windows volume root: %w", err)
	}
	if volumeInformation.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || volumeInformation.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		windows.CloseHandle(handle)
		return nil, errors.New("Windows volume root is a reparse point or non-directory")
	}
	current := os.NewFile(uintptr(handle), volumeRoot)
	if current == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("wrap Windows volume-root handle")
	}
	components := strings.Split(strings.TrimPrefix(path[len(volume):], `\`), `\`)
	for _, component := range components {
		if component == "" {
			continue
		}
		next, openErr := openDirectoryComponent(current, component)
		if openErr != nil {
			current.Close()
			return nil, openErr
		}
		if closeErr := current.Close(); closeErr != nil {
			next.Close()
			return nil, fmt.Errorf("close Windows directory-walk parent: %w", closeErr)
		}
		current = next
	}
	return current, nil
}

func openDirectoryComponent(parent *os.File, component string) (*os.File, error) {
	if parent == nil || component == "" || component == "." || component == ".." || strings.ContainsAny(component, `\/:`) {
		return nil, errors.New("Windows directory-walk component is invalid")
	}
	name, err := windows.NewNTUnicodeString(component)
	if err != nil {
		return nil, fmt.Errorf("encode Windows directory component: %w", err)
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: windows.Handle(parent.Fd()),
		ObjectName:    name,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		windows.FILE_READ_ATTRIBUTES|windows.FILE_TRAVERSE|windows.SYNCHRONIZE,
		&attributes,
		&status,
		nil,
		windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT,
		0,
		0,
	)
	runtime.KeepAlive(parent)
	runtime.KeepAlive(name)
	if err != nil {
		return nil, fmt.Errorf("open Windows directory component %q without reparsing: %w", component, err)
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("inspect Windows directory component %q: %w", component, err)
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("Windows directory component %q is a reparse point or non-directory", component)
	}
	file := os.NewFile(uintptr(handle), component)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("wrap Windows directory component %q", component)
	}
	return file, nil
}

// openNoReparseRoot converts the authenticated final handle into an os.Root
// and proves that both handles identify the same directory. The returned Root
// is therefore safe for later relative release operations even if the path is
// renamed after this function returns.
func openNoReparseRoot(path string) (*os.Root, os.FileInfo, error) {
	anchor, err := openNoReparseDirectory(path)
	if err != nil {
		return nil, nil, err
	}
	defer anchor.Close()
	anchoredInfo, err := anchor.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("stat no-reparse Windows directory: %w", err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open authenticated Windows directory root: %w", err)
	}
	rootInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(anchoredInfo, rootInfo) {
		root.Close()
		return nil, nil, errors.New("Windows directory changed while anchoring")
	}
	return root, rootInfo, nil
}
