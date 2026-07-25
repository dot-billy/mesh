package nebulaobserverartifact

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestVerifySecurityDependenciesRequiresExactLockedModules(t *testing.T) {
	newInfo := func() *debug.BuildInfo {
		dependencies := make([]*debug.Module, len(lockedSecurityDependencies))
		for index, locked := range lockedSecurityDependencies {
			dependencies[index] = &debug.Module{Path: locked.Path, Version: locked.Version, Sum: locked.Sum}
		}
		return &debug.BuildInfo{Deps: dependencies}
	}
	if err := verifySecurityDependencies(newInfo(), EntryLock{Name: "nebula"}, lockedSecurityDependencies); err != nil {
		t.Fatalf("exact security dependencies were rejected: %v", err)
	}
	certificateInfo := newInfo()
	certificateInfo.Deps = append(certificateInfo.Deps[:1], certificateInfo.Deps[2:]...)
	if err := verifySecurityDependencies(certificateInfo, EntryLock{Name: "nebula-cert"}, lockedSecurityDependencies); err != nil {
		t.Fatalf("nebula-cert was required to embed unused x/net: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*debug.BuildInfo)
		want   string
	}{
		{
			name: "missing required module",
			mutate: func(info *debug.BuildInfo) {
				info.Deps = info.Deps[1:]
			},
			want: "missing required security dependency",
		},
		{
			name: "wrong version",
			mutate: func(info *debug.BuildInfo) {
				info.Deps[1].Version = "v0.54.0"
			},
			want: "want \"v0.56.0\"",
		},
		{
			name: "replacement module",
			mutate: func(info *debug.BuildInfo) {
				info.Deps[0].Replace = &debug.Module{Path: "example.invalid/crypto", Version: "v1.0.0"}
			},
			want: "replaced=true",
		},
		{
			name: "duplicate module",
			mutate: func(info *debug.BuildInfo) {
				duplicate := *info.Deps[0]
				info.Deps = append(info.Deps, &duplicate)
			},
			want: "duplicate observer dependency",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := newInfo()
			test.mutate(info)
			err := verifySecurityDependencies(info, EntryLock{Name: "nebula"}, lockedSecurityDependencies)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
		})
	}
}
