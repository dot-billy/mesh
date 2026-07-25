package systemd

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestEmbeddedAssetsAreExactFreshCopies(t *testing.T) {
	tests := []struct {
		name string
		read func() []byte
	}{
		{name: "10-timeout-abort.conf", read: TimeoutAbortCompatibilityMask},
		{name: "mesh-agent.service", read: MeshAgentService},
		{name: "mesh-nebula.service", read: MeshNebulaService},
		{name: "README.md", read: README},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want, err := os.ReadFile(test.name)
			if err != nil {
				t.Fatal(err)
			}
			first := test.read()
			if !bytes.Equal(first, want) {
				t.Fatal("embedded bytes differ from source asset")
			}
			if len(first) == 0 {
				t.Fatal("embedded asset is empty")
			}
			first[0] ^= 0xff
			if got := test.read(); !bytes.Equal(got, want) {
				t.Fatal("mutating one asset copy changed a later copy")
			}
		})
	}
}

func TestTimeoutAbortCompatibilityMaskIsCommentOnly(t *testing.T) {
	content := string(TimeoutAbortCompatibilityMask())
	if strings.TrimSpace(content) == "" {
		t.Fatal("timeout-abort compatibility mask must not be empty")
	}
	for _, line := range strings.Split(strings.TrimSuffix(content, "\n"), "\n") {
		if strings.TrimSpace(line) == "" || !strings.HasPrefix(strings.TrimSpace(line), "#") {
			t.Fatalf("compatibility mask contains a non-comment line %q", line)
		}
	}
	if !strings.Contains(content, "TimeoutStopFailureMode=terminate") {
		t.Fatal("compatibility mask must document the restored systemd default")
	}
}

func TestBothManagedUnitsRequireExactInstallerRuntimeGate(t *testing.T) {
	const condition = "ConditionPathExists=/var/lib/mesh-installer/runtime.enabled"
	for name, content := range map[string]string{
		"mesh-agent.service":  string(MeshAgentService()),
		"mesh-nebula.service": string(MeshNebulaService()),
	} {
		if strings.Count(content, condition) != 1 {
			t.Fatalf("%s must contain exactly one fixed installer runtime condition", name)
		}
		if strings.Count(content, "Type=exec") != 1 || strings.Contains(content, "Type=simple") {
			t.Fatalf("%s must acknowledge startup only after the managed executable has been entered", name)
		}
	}
}

func TestPackagedNebulaRequiresEphemeralAgentReadiness(t *testing.T) {
	const condition = "ConditionPathExists=/run/mesh-agent/nebula.validated"
	agent := string(MeshAgentService())
	nebula := string(MeshNebulaService())
	if strings.Contains(agent, condition) {
		t.Fatal("mesh-agent.service must not depend on its own ephemeral child readiness marker")
	}
	if strings.Count(nebula, condition) != 1 {
		t.Fatal("mesh-nebula.service must contain exactly one fixed ephemeral readiness condition")
	}
	for _, directive := range []string{
		"RuntimeDirectory=mesh-agent",
		"RuntimeDirectoryMode=0700",
		"RuntimeDirectoryPreserve=no",
	} {
		if strings.Count(agent, directive) != 1 {
			t.Fatalf("mesh-agent.service must contain exactly one %q directive", directive)
		}
	}
	for _, directive := range []string{
		"RuntimeDirectory=mesh-nebula",
		"RuntimeDirectoryMode=0700",
		"RuntimeDirectoryPreserve=no",
	} {
		if strings.Count(nebula, directive) != 1 {
			t.Fatalf("mesh-nebula.service must contain exactly one %q directive", directive)
		}
	}
}

func TestPackagedAgentActiveProbeRetainsEmptyCapabilityBoundary(t *testing.T) {
	agent := string(MeshAgentService())
	for directive, count := range map[string]int{
		"NoNewPrivileges=yes":                                1,
		"CapabilityBoundingSet=":                             1,
		"ReadWritePaths=/var/lib/mesh-agent /run/mesh-agent": 1,
	} {
		if got := strings.Count(agent, directive); got != count {
			t.Fatalf("mesh-agent.service contains %d copies of %q, want %d", got, directive, count)
		}
	}
	if !strings.Contains(agent, "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK") {
		t.Fatal("mesh-agent.service must allow only the route observer's required netlink family in addition to its existing network families")
	}
	if strings.Count(agent, "ReadWritePaths=") != 1 {
		t.Fatal("mesh-agent.service must contain exactly one writable-path directive")
	}
	for _, forbidden := range []string{"AmbientCapabilities", "CAP_NET_RAW", "ReadWritePaths=/var/lib ", "ReadWritePaths=/tmp"} {
		if strings.Contains(agent, forbidden) {
			t.Fatalf("mesh-agent.service weakens its active-probe sandbox with %q", forbidden)
		}
	}
	if !strings.Contains(agent, "--state /var/lib/mesh-agent/state.json") {
		t.Fatal("mesh-agent.service no longer anchors the probe journal beneath /var/lib/mesh-agent")
	}
}
