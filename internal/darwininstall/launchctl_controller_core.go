package darwininstall

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	launchctlSystemDomain  = "system"
	launchctlServiceLabel  = "io.mesh.node-agent"
	launchctlServiceTarget = launchctlSystemDomain + "/" + launchctlServiceLabel
)

type launchctlCommandRunner interface {
	Run(arguments ...string) error
}

type launchctlServiceIdentity struct {
	domain string
	target string
}

func (identity launchctlServiceIdentity) resolve() (launchctlServiceIdentity, error) {
	if identity.domain == "" && identity.target == "" {
		return launchctlServiceIdentity{domain: launchctlSystemDomain, target: launchctlServiceTarget}, nil
	}
	if identity.domain != launchctlSystemDomain || !strings.HasPrefix(identity.target, identity.domain+"/") {
		return launchctlServiceIdentity{}, errors.New("launchctl service identity must name one system-domain target")
	}
	label := strings.TrimPrefix(identity.target, identity.domain+"/")
	if label == "" || len(label) > 255 || strings.ContainsAny(label, "/ \t\r\n") {
		return launchctlServiceIdentity{}, errors.New("launchctl service label is not canonical")
	}
	return identity, nil
}

type launchctlCommandContract struct {
	identity       launchctlServiceIdentity
	bootstrapPaths []string
}

func newLaunchctlCommandContract(identity launchctlServiceIdentity, bootstrapPaths ...string) (launchctlCommandContract, error) {
	resolved, err := identity.resolve()
	if err != nil {
		return launchctlCommandContract{}, err
	}
	if len(bootstrapPaths) == 0 || len(bootstrapPaths) > 2 {
		return launchctlCommandContract{}, errors.New("launchctl command contract requires one or two exact bootstrap plist paths")
	}
	paths := make([]string, len(bootstrapPaths))
	seen := make(map[string]struct{}, len(bootstrapPaths))
	for index, candidate := range bootstrapPaths {
		if !filepath.IsAbs(candidate) || filepath.Clean(candidate) != candidate || candidate == string(filepath.Separator) {
			return launchctlCommandContract{}, errors.New("launchctl bootstrap plist path is not canonical and absolute")
		}
		if _, duplicate := seen[candidate]; duplicate {
			return launchctlCommandContract{}, errors.New("launchctl command contract repeats a bootstrap plist path")
		}
		seen[candidate] = struct{}{}
		paths[index] = candidate
	}
	return launchctlCommandContract{identity: resolved, bootstrapPaths: paths}, nil
}

func (contract launchctlCommandContract) validate(arguments []string) error {
	identity, err := contract.identity.resolve()
	if err != nil || len(contract.bootstrapPaths) == 0 {
		return errors.Join(err, errors.New("launchctl command contract is incomplete"))
	}
	if len(arguments) == 2 && arguments[0] == "bootout" && arguments[1] == identity.target {
		return nil
	}
	if len(arguments) == 3 && arguments[0] == "bootstrap" && arguments[1] == identity.domain {
		for _, allowed := range contract.bootstrapPaths {
			if arguments[2] == allowed {
				return nil
			}
		}
	}
	return errors.New("launchctl command is outside its exact service/plist contract")
}

type launchctlServiceOperations struct {
	runner   launchctlCommandRunner
	identity launchctlServiceIdentity
}

// Bootout proves absence without interpreting launchctl output. A direct
// successful bootout is sufficient. If the service was already absent, the
// exact gate-closed recovery plist is bootstrapped first and a subsequent
// successful bootout establishes the same postcondition. A final bootout retry
// handles a race where the first removal failed but the recovery bootstrap
// correctly found an already-loaded definition.
func (operations launchctlServiceOperations) Bootout(recoveryPlist string) error {
	if operations.runner == nil || recoveryPlist == "" {
		return errors.New("launchctl bootout requires a runner and recovery plist")
	}
	identity, err := operations.identity.resolve()
	if err != nil {
		return err
	}
	firstBootout := operations.runner.Run("bootout", identity.target)
	if firstBootout == nil {
		return nil
	}
	recoveryBootstrap := operations.runner.Run("bootstrap", identity.domain, recoveryPlist)
	if recoveryBootstrap == nil {
		if err := operations.runner.Run("bootout", identity.target); err != nil {
			return fmt.Errorf("bootout service after recovery bootstrap: %w", err)
		}
		return nil
	}
	if retryBootout := operations.runner.Run("bootout", identity.target); retryBootout == nil {
		return nil
	} else {
		return errors.Join(
			errors.New("launchctl could not prove service absence"),
			fmt.Errorf("initial bootout: %w", firstBootout),
			fmt.Errorf("recovery bootstrap: %w", recoveryBootstrap),
			fmt.Errorf("final bootout: %w", retryBootout),
		)
	}
}

// Bootstrap proves loading only through a successful launchctl mutation. Its
// caller must have completed Bootout immediately beforehand under the installer
// transaction lock, so a collision cannot be mistaken for success.
func (operations launchctlServiceOperations) Bootstrap(livePlist string) error {
	if operations.runner == nil || livePlist == "" {
		return errors.New("launchctl bootstrap requires a runner and live plist")
	}
	identity, err := operations.identity.resolve()
	if err != nil {
		return err
	}
	if err := operations.runner.Run("bootstrap", identity.domain, livePlist); err != nil {
		return fmt.Errorf("bootstrap exact launchd service: %w", err)
	}
	return nil
}
