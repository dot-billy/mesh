//go:build linux

package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"mesh/internal/control"
)

type nativeDNSActiveState struct {
	policy        control.NativeDNSPolicy
	interfaceName string
	proxy         nativeDNSProxyHandle
}

type linuxNativeDNSManager struct {
	runner         CommandRunner
	interfaceForIP func(netip.Addr) (string, error)
	startProxy     func(control.NativeDNSPolicy) (nativeDNSProxyHandle, error)
	mu             sync.Mutex
	active         *nativeDNSActiveState
}

func NewNativeDNSManager(runner CommandRunner) NativeDNSReconciler {
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	return &linuxNativeDNSManager{
		runner: runner, interfaceForIP: nativeDNSInterfaceForIP, startProxy: startNativeDNSProxy,
	}
}

func (m *linuxNativeDNSManager) Reconcile(ctx context.Context, signedConfig string) error {
	policy, enabled, err := parseNativeDNSConfig(signedConfig)
	if err != nil {
		return err
	}
	if !enabled {
		return m.Disable(ctx)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.runner == nil || m.interfaceForIP == nil || m.startProxy == nil {
		return errors.New("native DNS manager dependencies are unavailable")
	}
	localIP, err := netip.ParseAddr(policy.LocalIP)
	if err != nil {
		return errors.New("signed native DNS local address is invalid")
	}
	interfaceName, err := m.interfaceForIP(localIP)
	if err != nil {
		return fmt.Errorf("locate native DNS overlay interface: %w", err)
	}
	if m.active != nil && reflect.DeepEqual(m.active.policy, policy) && m.active.interfaceName == interfaceName && m.active.proxy != nil {
		// systemd-resolved may restart independently and lose its transient
		// per-link state. Reassert the same values without restarting the local
		// adapter so the next bounded lifecycle cycle repairs that loss.
		return m.apply(ctx, m.active)
	}
	proxy, err := m.startProxy(policy)
	if err != nil {
		return err
	}
	next := &nativeDNSActiveState{policy: policy, interfaceName: interfaceName, proxy: proxy}
	if err := m.apply(ctx, next); err != nil {
		_ = proxy.Close()
		_ = m.revert(ctx, interfaceName)
		if m.active != nil && m.active.proxy != nil {
			_ = m.apply(ctx, m.active)
		}
		return err
	}
	previous := m.active
	if previous != nil && previous.interfaceName != interfaceName {
		if err := m.revert(ctx, previous.interfaceName); err != nil {
			_ = m.revert(ctx, interfaceName)
			_ = proxy.Close()
			if previous.proxy != nil {
				_ = m.apply(ctx, previous)
			}
			return fmt.Errorf("remove previous native DNS interface state: %w", err)
		}
	}
	m.active = next
	if previous != nil && previous.proxy != nil {
		_ = previous.proxy.Close()
	}
	return nil
}

func (m *linuxNativeDNSManager) Disable(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return nil
	}
	active := m.active
	if active.proxy != nil {
		_ = active.proxy.Close()
		active.proxy = nil
	}
	if err := m.revert(ctx, active.interfaceName); err != nil {
		return fmt.Errorf("revert native DNS interface state: %w", err)
	}
	m.active = nil
	return nil
}

func (m *linuxNativeDNSManager) apply(ctx context.Context, active *nativeDNSActiveState) error {
	if active == nil || active.proxy == nil || active.proxy.Port() < 1 || active.proxy.Port() > 65535 {
		return errors.New("native DNS adapter listener is invalid")
	}
	server := net.JoinHostPort(active.policy.LocalIP, strconv.Itoa(active.proxy.Port()))
	commands := [][]string{
		{"dns", active.interfaceName, server},
		{"domain", active.interfaceName, active.policy.SearchDomain},
		{"default-route", active.interfaceName, "false"},
		{"dnssec", active.interfaceName, "no"},
		{"dnsovertls", active.interfaceName, "no"},
		{"llmnr", active.interfaceName, "no"},
		{"mdns", active.interfaceName, "no"},
	}
	for _, arguments := range commands {
		if err := m.runner.RunQuiet(ctx, "resolvectl", arguments...); err != nil {
			return fmt.Errorf("configure native DNS %s: %w", arguments[0], err)
		}
	}
	return nil
}

func (m *linuxNativeDNSManager) revert(ctx context.Context, interfaceName string) error {
	if strings.TrimSpace(interfaceName) == "" {
		return nil
	}
	return m.runner.RunQuiet(ctx, "resolvectl", "revert", interfaceName)
}

func nativeDNSInterfaceForIP(address netip.Addr) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", errors.New("network interface inventory is unavailable")
	}
	if len(interfaces) > 256 {
		return "", errors.New("network interface inventory exceeds the safety bound")
	}
	result := ""
	for _, candidate := range interfaces {
		if candidate.Flags&net.FlagLoopback != 0 || candidate.Name == "" || len(candidate.Name) > 15 {
			continue
		}
		addresses, err := candidate.Addrs()
		if err != nil || len(addresses) > 64 {
			return "", errors.New("network interface addresses are unavailable")
		}
		for _, value := range addresses {
			prefix, err := netip.ParsePrefix(value.String())
			if err == nil && prefix.Addr().Unmap() == address {
				if result != "" && result != candidate.Name {
					return "", errors.New("native DNS local address is present on multiple interfaces")
				}
				result = candidate.Name
			}
		}
	}
	if result == "" {
		return "", errors.New("native DNS local address is not present on a non-loopback interface")
	}
	return result, nil
}
