package nodeagent

import (
	"strings"
	"testing"
)

func validDarwinRuntimeGateSnapshot() darwinRuntimeGateSnapshot {
	return darwinRuntimeGateSnapshot{
		device: 1, inode: 2, mode: darwinModeRegularFile | darwinRuntimeGateMode,
		links: 1, size: int64(len(darwinPersistentRuntimeGateContent)),
	}
}

func TestValidateDarwinPersistentRuntimeGateRequiresExactSnapshotAndContent(t *testing.T) {
	valid := validDarwinRuntimeGateSnapshot()
	if err := validateDarwinPersistentRuntimeGate(valid, darwinPersistentRuntimeGateContent); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*darwinRuntimeGateSnapshot)
		body   []byte
		want   string
	}{
		{name: "directory", mutate: func(value *darwinRuntimeGateSnapshot) { value.mode = 0040000 | darwinRuntimeGateMode }, body: darwinPersistentRuntimeGateContent, want: "regular file"},
		{name: "broad mode", mutate: func(value *darwinRuntimeGateSnapshot) { value.mode = darwinModeRegularFile | 0o440 }, body: darwinPersistentRuntimeGateContent, want: "mode-0400"},
		{name: "non-root owner", mutate: func(value *darwinRuntimeGateSnapshot) { value.uid = 501 }, body: darwinPersistentRuntimeGateContent, want: "root:wheel"},
		{name: "non-wheel group", mutate: func(value *darwinRuntimeGateSnapshot) { value.gid = 20 }, body: darwinPersistentRuntimeGateContent, want: "root:wheel"},
		{name: "hard link", mutate: func(value *darwinRuntimeGateSnapshot) { value.links = 2 }, body: darwinPersistentRuntimeGateContent, want: "singly linked"},
		{name: "file flags", mutate: func(value *darwinRuntimeGateSnapshot) { value.flags = 2 }, body: darwinPersistentRuntimeGateContent, want: "file flags"},
		{name: "wrong size", mutate: func(value *darwinRuntimeGateSnapshot) { value.size-- }, body: darwinPersistentRuntimeGateContent, want: "reviewed authorization"},
		{name: "wrong bytes", mutate: func(value *darwinRuntimeGateSnapshot) {}, body: []byte("mesh-runtime-disabled-v1\n"), want: "reviewed authorization"},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := valid
			test.mutate(&snapshot)
			if err := validateDarwinPersistentRuntimeGate(snapshot, test.body); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want text %q", err, test.want)
			}
		})
	}
}
