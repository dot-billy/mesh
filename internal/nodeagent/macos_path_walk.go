package nodeagent

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

type darwinPathWalkOperations struct {
	openRoot   func() (int, error)
	openAt     func(parent int, name string, requireDirectory bool) (int, error)
	inspect    func(fd int, path string, ancestor bool) error
	close      func(fd int) error
	isNotExist func(error) bool
}

// validateDarwinPathWith walks an absolute, canonical path from an opened root
// and never follows a pathname component. An absent suffix is acceptable: the
// state and bundle callers separately require their immediate creation parent
// before mutating anything.
func validateDarwinPathWith(path string, operations darwinPathWalkOperations) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("sensitive Darwin path must be absolute and canonical")
	}
	if operations.openRoot == nil || operations.openAt == nil || operations.inspect == nil || operations.close == nil || operations.isNotExist == nil {
		return errors.New("Darwin path-security operations are incomplete")
	}
	current, err := operations.openRoot()
	if err != nil {
		return fmt.Errorf("open Darwin filesystem root without symlinks: %w", err)
	}
	defer func() { _ = operations.close(current) }()
	if err := operations.inspect(current, string(filepath.Separator), true); err != nil {
		return err
	}
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	if len(components) == 1 && components[0] == "" {
		return nil
	}
	currentPath := string(filepath.Separator)
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			return errors.New("sensitive Darwin path contains an invalid component")
		}
		ancestor := index != len(components)-1
		next, openErr := operations.openAt(current, component, ancestor)
		if operations.isNotExist(openErr) {
			return nil
		}
		if openErr != nil {
			return fmt.Errorf("open sensitive Darwin path component %q without symlinks: %w", component, openErr)
		}
		nextPath := filepath.Join(currentPath, component)
		if inspectErr := operations.inspect(next, nextPath, ancestor); inspectErr != nil {
			_ = operations.close(next)
			return inspectErr
		}
		if closeErr := operations.close(current); closeErr != nil {
			_ = operations.close(next)
			return fmt.Errorf("close sensitive Darwin path component %q: %w", currentPath, closeErr)
		}
		current = next
		currentPath = nextPath
	}
	return nil
}
