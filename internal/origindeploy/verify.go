package origindeploy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"mesh/internal/originimage"
	"mesh/internal/releaseorigin"
)

const (
	DefaultTimeout = 30 * time.Second
	MaxTimeout     = 5 * time.Minute
	maxDockerJSON  = 2 << 20
)

type Config struct {
	ImageReceipt    string
	SecurityReceipt string
	ComposeConfig   string
	Generation      string
	ContainerID     string
	DockerPath      string
	DockerSocket    string
	Timeout         time.Duration
}

type Runner interface {
	InspectContainer(context.Context, string, string, string) ([]byte, error)
	InspectImage(context.Context, string, string, string) ([]byte, error)
}

type GenerationInspector func(string) (releaseorigin.GenerationReceipt, error)

type ExecRunner struct{}

func (ExecRunner) InspectContainer(ctx context.Context, dockerPath, socketPath, containerID string) ([]byte, error) {
	return runDocker(ctx, dockerPath, socketPath, "container", containerID)
}

func (ExecRunner) InspectImage(ctx context.Context, dockerPath, socketPath, imageID string) ([]byte, error) {
	return runDocker(ctx, dockerPath, socketPath, "image", "sha256:"+imageID)
}

func runDocker(ctx context.Context, dockerPath, socketPath, kind, identity string) ([]byte, error) {
	var output boundedBuffer
	output.maximum = maxDockerJSON
	command := exec.CommandContext(ctx, dockerPath, "--host", "unix://"+socketPath, kind, "inspect", identity)
	command.Env = []string{"PATH=/usr/bin:/bin"}
	command.Stdin = bytes.NewReader(nil)
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("Docker inspection deadline: %w", ctx.Err())
		}
		return nil, fmt.Errorf("Docker could not inspect the exact origin %s", kind)
	}
	if output.overflow {
		return nil, fmt.Errorf("Docker %s inspection exceeded %d bytes", kind, maxDockerJSON)
	}
	return output.Bytes(), nil
}

type boundedBuffer struct {
	bytes.Buffer
	maximum  int
	overflow bool
}

func (writer *boundedBuffer) Write(raw []byte) (int, error) {
	remaining := writer.maximum - writer.Len()
	if remaining <= 0 {
		writer.overflow = true
		return len(raw), nil
	}
	if len(raw) > remaining {
		writer.overflow = true
		_, _ = writer.Buffer.Write(raw[:remaining])
		return len(raw), nil
	}
	return writer.Buffer.Write(raw)
}

func Verify(ctx context.Context, config Config, clock func() time.Time, runner Runner, inspectGeneration GenerationInspector) (Receipt, error) {
	if ctx == nil || clock == nil || runner == nil || inspectGeneration == nil {
		return Receipt{}, errors.New("origin runtime verification requires context, clock, Docker runner, and generation inspector")
	}
	if config.Timeout <= 0 || config.Timeout > MaxTimeout {
		return Receipt{}, fmt.Errorf("origin runtime verification timeout must be positive and no greater than %s", MaxTimeout)
	}
	if !validDigest(config.ContainerID) {
		return Receipt{}, errors.New("origin container ID must be exactly 64 lowercase hexadecimal characters")
	}
	imageReceipt, _, imageReceiptDigest, err := originimage.ReadReceiptFile(config.ImageReceipt)
	if err != nil {
		return Receipt{}, err
	}
	securityReceipt, securityReceiptDigest, err := readOriginSecurityReceipt(config.SecurityReceipt)
	if err != nil {
		return Receipt{}, err
	}
	composeRaw, composeDigest, err := readStableFile(config.ComposeConfig, "rendered production Compose", maxComposeConfig)
	if err != nil {
		return Receipt{}, err
	}
	if !filepath.IsAbs(config.Generation) || filepath.Clean(config.Generation) != config.Generation || filepath.Base(config.Generation) == "." {
		return Receipt{}, errors.New("origin generation must be a clean absolute path")
	}
	generationBefore, err := inspectGeneration(config.Generation)
	if err != nil {
		return Receipt{}, err
	}
	if generationBefore.Schema != releaseorigin.GenerationSchema || generationBefore.ObjectCount < 1 ||
		generationBefore.ObjectCount > releaseorigin.MaxObjects || generationBefore.TotalSize < 1 ||
		generationBefore.Generation != imageGenerationName(config.Generation) || generationBefore.Generation != generationBefore.IndexSHA256 {
		return Receipt{}, errors.New("inspected origin generation path and receipt are inconsistent")
	}
	selection, err := parseCompose(composeRaw, imageReceipt.Image, config.Generation)
	if err != nil {
		return Receipt{}, err
	}
	if selection.image.digest != imageReceipt.ManifestSHA256 {
		return Receipt{}, errors.New("rendered Compose manifest differs from the image receipt")
	}
	dockerSocketBefore, err := inspectDockerSocket(config.DockerSocket)
	if err != nil {
		return Receipt{}, err
	}
	dockerDigestBefore, err := originimage.HashExecutable(config.DockerPath, "Docker executable")
	if err != nil {
		return Receipt{}, err
	}
	deadlineContext, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	containerRaw, err := runner.InspectContainer(deadlineContext, config.DockerPath, config.DockerSocket, config.ContainerID)
	if err != nil {
		return Receipt{}, err
	}
	container, err := decodeOne[containerInspect](containerRaw, "container inspection")
	if err != nil {
		return Receipt{}, err
	}
	localImageID, err := validateContainer(container, config.ContainerID, selection)
	if err != nil {
		return Receipt{}, err
	}
	securityImageID := strings.TrimPrefix(securityReceipt.Image.DockerImageID, "sha256:")
	if localImageID != securityImageID {
		return Receipt{}, errors.New("running origin image differs from the image-security receipt")
	}
	imageRaw, err := runner.InspectImage(deadlineContext, config.DockerPath, config.DockerSocket, localImageID)
	if err != nil {
		return Receipt{}, err
	}
	localImage, err := decodeOne[imageInspect](imageRaw, "image inspection")
	if err != nil {
		return Receipt{}, err
	}
	if err := validateImage(localImage, localImageID, imageReceipt.Image); err != nil {
		return Receipt{}, err
	}
	if localImage.OS+"/"+localImage.Architecture != securityReceipt.Image.Platform {
		return Receipt{}, errors.New("running origin platform differs from the image-security receipt")
	}
	dockerDigestAfter, err := originimage.HashExecutable(config.DockerPath, "Docker executable")
	if err != nil {
		return Receipt{}, err
	}
	if dockerDigestBefore != dockerDigestAfter {
		return Receipt{}, errors.New("Docker executable changed during origin runtime verification")
	}
	if !sameDockerSocket(config.DockerSocket, dockerSocketBefore) {
		return Receipt{}, errors.New("Docker socket changed during origin runtime verification")
	}
	generationAfter, err := inspectGeneration(config.Generation)
	if err != nil || generationAfter != generationBefore {
		return Receipt{}, errors.New("origin generation changed during runtime verification")
	}
	verifiedAt := clock()
	if verifiedAt.Location() != time.UTC {
		return Receipt{}, errors.New("origin runtime verification clock must return UTC")
	}
	receipt := Receipt{
		Schema: ReceiptSchema, ImageReceiptSHA256: imageReceiptDigest, SecurityReceiptSHA256: securityReceiptDigest,
		Image: imageReceipt.Image, ManifestSHA256: imageReceipt.ManifestSHA256,
		ComposeSHA256: composeDigest, Generation: generationBefore.Generation,
		ContainerID: config.ContainerID, LocalImageID: localImageID,
		DockerSHA256: dockerDigestAfter, PublicURL: selection.publicURL,
		RuntimeUser: selection.user, VerifiedAt: verifiedAt.Format(time.RFC3339Nano),
	}
	if err := validateReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func imageGenerationName(path string) string { return filepath.Base(path) }
