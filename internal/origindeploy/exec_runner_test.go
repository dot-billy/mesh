//go:build !windows

package origindeploy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExecRunnerUsesExplicitSocketKindAndExactIdentity(t *testing.T) {
	directory := t.TempDir()
	dockerPath := filepath.Join(directory, "docker")
	socketPath := filepath.Join(directory, "docker.sock")
	containerID := strings.Repeat("c", 64)
	imageID := strings.Repeat("d", 64)
	script := `#!/bin/sh
set -eu
[ "$#" -eq 5 ]
[ "$1" = "--host" ]
[ "$2" = "unix://` + socketPath + `" ]
[ "$4" = "inspect" ]
case "$3" in
  container) [ "$5" = "` + containerID + `" ]; printf '[{"Id":"` + containerID + `"}]' ;;
  image) [ "$5" = "sha256:` + imageID + `" ]; printf '[{"Id":"sha256:` + imageID + `"}]' ;;
  *) exit 9 ;;
esac
`
	if err := os.WriteFile(dockerPath, []byte(script), 0o555); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	runner := ExecRunner{}
	containerRaw, err := runner.InspectContainer(ctx, dockerPath, socketPath, containerID)
	if err != nil || !strings.Contains(string(containerRaw), containerID) {
		t.Fatalf("container inspect = %q, %v", containerRaw, err)
	}
	imageRaw, err := runner.InspectImage(ctx, dockerPath, socketPath, imageID)
	if err != nil || !strings.Contains(string(imageRaw), imageID) {
		t.Fatalf("image inspect = %q, %v", imageRaw, err)
	}
}
