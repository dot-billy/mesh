package nodeagent

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var errDarwinWalkMissing = errors.New("missing")

func TestValidateDarwinPathWithInspectsOpenedChainAndAcceptsAbsentSuffix(t *testing.T) {
	var inspected []string
	var closed []int
	nextFD := 10
	operations := darwinPathWalkOperations{
		openRoot: func() (int, error) { return 9, nil },
		openAt: func(parent int, name string, requireDirectory bool) (int, error) {
			if name == "mesh-agent" {
				return -1, errDarwinWalkMissing
			}
			nextFD++
			return nextFD, nil
		},
		inspect: func(_ int, path string, _ bool) error {
			inspected = append(inspected, path)
			return nil
		},
		close:      func(fd int) error { closed = append(closed, fd); return nil },
		isNotExist: func(err error) bool { return errors.Is(err, errDarwinWalkMissing) },
	}
	if err := validateDarwinPathWith("/private/var/db/mesh-agent/state.json", operations); err != nil {
		t.Fatal(err)
	}
	wantInspected := []string{"/", "/private", "/private/var", "/private/var/db"}
	if !reflect.DeepEqual(inspected, wantInspected) {
		t.Fatalf("inspected = %v, want %v", inspected, wantInspected)
	}
	if len(closed) != 4 || closed[len(closed)-1] != 13 {
		t.Fatalf("closed descriptors = %v, want every opened descriptor exactly once", closed)
	}
}

func TestValidateDarwinPathWithRejectsInvalidPathAndInjectedFailures(t *testing.T) {
	validOperations := func() darwinPathWalkOperations {
		return darwinPathWalkOperations{
			openRoot:   func() (int, error) { return 3, nil },
			openAt:     func(parent int, name string, requireDirectory bool) (int, error) { return parent + 1, nil },
			inspect:    func(int, string, bool) error { return nil },
			close:      func(int) error { return nil },
			isNotExist: func(error) bool { return false },
		}
	}
	for _, path := range []string{"relative", "/private/../var", "/private//var"} {
		if err := validateDarwinPathWith(path, validOperations()); err == nil {
			t.Fatalf("invalid path %q was accepted", path)
		}
	}

	operations := validOperations()
	operations.openAt = func(int, string, bool) (int, error) { return -1, errors.New("symbolic link") }
	if err := validateDarwinPathWith("/private/var", operations); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("open failure = %v", err)
	}

	operations = validOperations()
	operations.inspect = func(_ int, path string, _ bool) error { return fmt.Errorf("unsafe %s", path) }
	if err := validateDarwinPathWith("/private/var", operations); err == nil || !strings.Contains(err.Error(), "unsafe /") {
		t.Fatalf("inspection failure = %v", err)
	}

	operations = validOperations()
	operations.close = func(int) error { return errors.New("close failed") }
	if err := validateDarwinPathWith("/private", operations); err == nil || !strings.Contains(err.Error(), "close failed") {
		t.Fatalf("close failure = %v", err)
	}
}
