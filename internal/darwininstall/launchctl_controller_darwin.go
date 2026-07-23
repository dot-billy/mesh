//go:build darwin

package darwininstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"mesh/internal/darwinbundle"
	"mesh/internal/nodeagent"

	"golang.org/x/sys/unix"
)

const (
	productionLaunchctlPath = "/bin/launchctl"
	launchctlCommandTimeout = 30 * time.Second
	launchctlOutputLimit    = 64 << 10
)

// ProductionLaunchctlServiceController proves state through successful
// launchctl mutations only. It never invokes print/list or parses output that
// Apple explicitly excludes from its API contract.
type ProductionLaunchctlServiceController struct {
	mu sync.Mutex

	layout        *ReleaseLayout
	installedID   string
	inspection    darwinbundle.CandidateInspection
	recoveryPlist string
	livePlist     string
	operations    launchctlServiceOperations
}

func NewProductionLaunchctlServiceController(layout *ReleaseLayout, installedID string, inspection darwinbundle.CandidateInspection) (*ProductionLaunchctlServiceController, error) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return nil, errors.New("production launchctl control requires root:wheel execution")
	}
	if layout == nil || !darwinInstalledIDPattern.MatchString(installedID) {
		return nil, errors.New("production launchctl control requires a canonical release identity")
	}
	if err := darwinbundle.ValidateCandidateInspection(inspection); err != nil {
		return nil, err
	}
	if !strings.HasSuffix(installedID, "-a"+inspection.ArtifactSHA256[:16]) {
		return nil, errors.New("production launchctl release identity differs from its bundle inspection")
	}
	inspection.Package.Entries = append([]darwinbundle.Entry(nil), inspection.Package.Entries...)
	recoveryPlist := filepath.Join(layout.releasesPath, installedID, launchdPlistReleasePath)
	livePlist := filepath.Join(ProductionLaunchdDirectory, LaunchdPlistName)
	if !cleanDarwinInstallPath(recoveryPlist) || !cleanDarwinInstallPath(livePlist) {
		return nil, errors.New("production launchctl plist paths are invalid")
	}
	if _, err := authenticateProductionLaunchctl(); err != nil {
		return nil, err
	}
	contract, err := newLaunchctlCommandContract(
		launchctlServiceIdentity{domain: launchctlSystemDomain, target: launchctlServiceTarget},
		recoveryPlist,
		livePlist,
	)
	if err != nil {
		return nil, err
	}
	return &ProductionLaunchctlServiceController{
		layout: layout, installedID: installedID, inspection: inspection,
		recoveryPlist: recoveryPlist, livePlist: livePlist,
		operations: launchctlServiceOperations{
			runner:   productionLaunchctlCommandRunner{contract: contract},
			identity: contract.identity,
		},
	}, nil
}

func (controller *ProductionLaunchctlServiceController) ValidateInstallerJournal(journal InstallerJournal) error {
	if controller == nil {
		return errors.New("production launchctl controller is required")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if journal.InstalledID != controller.installedID || !reflect.DeepEqual(journal.Inspection, controller.inspection) {
		return errors.New("production launchctl controller differs from the installer journal")
	}
	return nil
}

func (controller *ProductionLaunchctlServiceController) Bootout() error {
	if controller == nil {
		return errors.New("production launchctl controller is required")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if _, err := readAuthenticatedLaunchdPlist(controller.layout, controller.installedID, controller.inspection); err != nil {
		return fmt.Errorf("authenticate launchctl recovery plist: %w", err)
	}
	return controller.operations.Bootout(controller.recoveryPlist)
}

func (controller *ProductionLaunchctlServiceController) Bootstrap() error {
	if controller == nil {
		return errors.New("production launchctl controller is required")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	publisher, err := NewProductionLaunchdPlistPublisher(controller.layout, controller.installedID, controller.inspection)
	if err != nil {
		return err
	}
	inspectErr := publisher.Inspect()
	closeErr := publisher.Close()
	if err := errors.Join(inspectErr, closeErr); err != nil {
		return fmt.Errorf("authenticate live launchctl plist: %w", err)
	}
	return controller.operations.Bootstrap(controller.livePlist)
}

type productionLaunchctlCommandRunner struct {
	contract launchctlCommandContract
}

func (runner productionLaunchctlCommandRunner) Run(arguments ...string) error {
	if err := runner.contract.validate(arguments); err != nil {
		return err
	}
	before, err := authenticateProductionLaunchctl()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), launchctlCommandTimeout)
	defer cancel()
	var stdout, stderr boundedLaunchctlOutput
	command := exec.CommandContext(ctx, productionLaunchctlPath, arguments...)
	command.Env = []string{}
	command.Dir = "/"
	command.Stdin = bytes.NewReader(nil)
	command.Stdout = &stdout
	command.Stderr = &stderr
	command.WaitDelay = 5 * time.Second
	runErr := command.Run()
	after, authErr := authenticateProductionLaunchctl()
	if authErr != nil || before != after {
		return errors.Join(runErr, authErr, errors.New("/bin/launchctl changed while executing the installer operation"))
	}
	if ctx.Err() != nil {
		return fmt.Errorf("launchctl %s exceeded its timeout: %w", arguments[0], ctx.Err())
	}
	if stdout.overflow || stderr.overflow {
		return fmt.Errorf("launchctl %s output exceeded its bound", arguments[0])
	}
	if runErr != nil {
		return fmt.Errorf("launchctl %s failed: %w; stdout=%s stderr=%s", arguments[0], runErr, launchctlOutputIdentity(stdout.Bytes()), launchctlOutputIdentity(stderr.Bytes()))
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		return fmt.Errorf("launchctl %s succeeded with unexpected output; stdout=%s stderr=%s", arguments[0], launchctlOutputIdentity(stdout.Bytes()), launchctlOutputIdentity(stderr.Bytes()))
	}
	return nil
}

type boundedLaunchctlOutput struct {
	bytes.Buffer
	overflow bool
}

func (output *boundedLaunchctlOutput) Write(content []byte) (int, error) {
	remaining := launchctlOutputLimit - output.Len()
	if remaining <= 0 {
		output.overflow = true
		return 0, errors.New("launchctl output limit reached")
	}
	if len(content) > remaining {
		written, _ := output.Buffer.Write(content[:remaining])
		output.overflow = true
		return written, errors.New("launchctl output limit reached")
	}
	return output.Buffer.Write(content)
}

func launchctlOutputIdentity(content []byte) string {
	digest := sha256.Sum256(content)
	return fmt.Sprintf("%d-bytes-sha256-%s", len(content), hex.EncodeToString(digest[:]))
}

func authenticateProductionLaunchctl() (darwinInstallStatSnapshot, error) {
	if err := nodeagent.InspectDarwinSensitivePath(productionLaunchctlPath); err != nil {
		return darwinInstallStatSnapshot{}, fmt.Errorf("authenticate /bin/launchctl path: %w", err)
	}
	var before, opened, after unix.Stat_t
	if err := unix.Lstat(productionLaunchctlPath, &before); err != nil {
		return darwinInstallStatSnapshot{}, err
	}
	fd, err := unix.Open(productionLaunchctlPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY|unix.O_NONBLOCK, 0)
	if err != nil {
		return darwinInstallStatSnapshot{}, err
	}
	file := os.NewFile(uintptr(fd), productionLaunchctlPath)
	if file == nil {
		_ = unix.Close(fd)
		return darwinInstallStatSnapshot{}, errors.New("adopt /bin/launchctl descriptor")
	}
	defer file.Close()
	if err := unix.Fstat(fd, &opened); err != nil {
		return darwinInstallStatSnapshot{}, err
	}
	if err := unix.Lstat(productionLaunchctlPath, &after); err != nil {
		return darwinInstallStatSnapshot{}, err
	}
	for _, stat := range []unix.Stat_t{before, opened, after} {
		mode := stat.Mode & 0o7777
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 ||
			mode&0o022 != 0 || mode&0o111 == 0 || stat.Size < 1 || stat.Size > 64<<20 {
			return darwinInstallStatSnapshot{}, errors.New("/bin/launchctl must remain one bounded root:wheel nonwritable executable")
		}
	}
	snapshot := snapshotDarwinInstallStat(before)
	if snapshot != snapshotDarwinInstallStat(opened) || snapshot != snapshotDarwinInstallStat(after) {
		return darwinInstallStatSnapshot{}, errors.New("/bin/launchctl changed while authenticating its descriptor")
	}
	if err := nodeagent.InspectDarwinSensitivePath(productionLaunchctlPath); err != nil {
		return darwinInstallStatSnapshot{}, err
	}
	return snapshot, nil
}
