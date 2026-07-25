package nodeagent

import (
	"strings"
	"testing"
)

func TestValidateDarwinPackagedExecutableRequiresExactSnapshot(t *testing.T) {
	valid := darwinRuntimeGateSnapshot{
		device: 1, inode: 2, mode: darwinModeRegularFile | darwinPackagedExecutableMode,
		links: 1, size: 4096,
	}
	if err := validateDarwinPackagedExecutable(valid); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*darwinRuntimeGateSnapshot)
		want   string
	}{
		{name: "directory", mutate: func(value *darwinRuntimeGateSnapshot) { value.mode = 0040000 | darwinPackagedExecutableMode }, want: "regular file"},
		{name: "writable", mutate: func(value *darwinRuntimeGateSnapshot) { value.mode = darwinModeRegularFile | 0o755 }, want: "mode-0555"},
		{name: "non-root owner", mutate: func(value *darwinRuntimeGateSnapshot) { value.uid = 501 }, want: "root:wheel"},
		{name: "non-wheel group", mutate: func(value *darwinRuntimeGateSnapshot) { value.gid = 20 }, want: "root:wheel"},
		{name: "hard link", mutate: func(value *darwinRuntimeGateSnapshot) { value.links = 2 }, want: "singly linked"},
		{name: "file flags", mutate: func(value *darwinRuntimeGateSnapshot) { value.flags = 2 }, want: "file flags"},
		{name: "empty", mutate: func(value *darwinRuntimeGateSnapshot) { value.size = 0 }, want: "empty"},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := valid
			test.mutate(&snapshot)
			if err := validateDarwinPackagedExecutable(snapshot); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want text %q", err, test.want)
			}
		})
	}
}
