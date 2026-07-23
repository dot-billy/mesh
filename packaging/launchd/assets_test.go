package launchd

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
		{name: "io.mesh.node-agent.plist", read: NodeAgentPlist},
		{name: "README.md", read: README},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want, err := os.ReadFile(test.name)
			if err != nil {
				t.Fatal(err)
			}
			first := test.read()
			if len(first) == 0 || !bytes.Equal(first, want) {
				t.Fatal("embedded bytes differ from the non-empty source asset")
			}
			first[0] ^= 0xff
			if got := test.read(); !bytes.Equal(got, want) {
				t.Fatal("mutating one asset copy changed a later copy")
			}
		})
	}
}

func TestNodeAgentPlistHasOneExactRootOwnedChildSupervisorContract(t *testing.T) {
	content := string(NodeAgentPlist())
	requiredOnce := []string{
		"<string>io.mesh.node-agent</string>",
		"<string>/opt/mesh/current/bin/meshctl</string>",
		"<string>/private/var/db/mesh-agent/state.json</string>",
		"<string>/opt/mesh/current/bin/nebula</string>",
		"<string>/opt/mesh/current/bin/nebula-cert</string>",
		"<string>--supervise-nebula</string>",
		"<key>/private/var/db/mesh-installer/runtime.enabled</key>",
		"<string>root</string>",
		"<string>wheel</string>",
		"<key>AbandonProcessGroup</key>",
	}
	for _, value := range requiredOnce {
		if strings.Count(content, value) != 1 {
			t.Fatalf("launchd contract must contain exactly one %q", value)
		}
	}
	for _, forbidden := range []string{
		"io.mesh.nebula", "/bin/sh", "/bin/bash", "EnvironmentVariables",
		"WatchPaths", "QueueDirectories", "StandardOutPath", "StandardErrorPath",
		"/usr/local", "--fail-open", "--no-reload",
	} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("launchd contract contains forbidden alternate or mutable surface %q", forbidden)
		}
	}
	if strings.Count(content, "<key>Label</key>") != 1 ||
		strings.Count(content, "<key>ProgramArguments</key>") != 1 ||
		strings.Count(content, "<key>KeepAlive</key>") != 1 ||
		strings.Count(content, "<key>PathState</key>") != 1 {
		t.Fatal("launchd contract does not contain one exact job and persistent-gate trigger")
	}
}

func TestLaunchdREADMEDoesNotClaimNativeSupport(t *testing.T) {
	content := string(README())
	for _, phrase := range []string{
		"Do not copy or bootstrap the plist manually",
		"There is intentionally no independent Nebula LaunchDaemon",
		"It is not the security boundary",
		"The cross-built adapter authenticates",
		"None of those native calls has executed on a Mac",
		"requires native fault-injection proof",
	} {
		if !strings.Contains(content, phrase) {
			t.Fatalf("launchd README is missing limitation %q", phrase)
		}
	}
}
