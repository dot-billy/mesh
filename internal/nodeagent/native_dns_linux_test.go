//go:build linux

package nodeagent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/miekg/dns"
	"mesh/internal/control"
)

type nativeDNSRecordingRunner struct {
	commands [][]string
	failAt   int
}

func (*nativeDNSRecordingRunner) Output(context.Context, string, ...string) ([]byte, error) {
	return nil, errors.New("unexpected output command")
}

func (r *nativeDNSRecordingRunner) RunQuiet(_ context.Context, name string, args ...string) error {
	command := append([]string{name}, args...)
	r.commands = append(r.commands, command)
	if r.failAt > 0 && len(r.commands) == r.failAt {
		return errors.New("injected resolver failure")
	}
	return nil
}

type nativeDNSFakeProxy struct {
	port   int
	closed int
}

func (p *nativeDNSFakeProxy) Port() int    { return p.port }
func (p *nativeDNSFakeProxy) Close() error { p.closed++; return nil }

func nativeDNSSignedConfig(t *testing.T, policy control.NativeDNSPolicy) string {
	t.Helper()
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	return control.NativeDNSPolicyPrefix + base64.RawURLEncoding.EncodeToString(raw) + "\npki:\n"
}

func testNativeDNSPolicy() control.NativeDNSPolicy {
	return control.NativeDNSPolicy{
		Schema: control.NativeDNSPolicySchema, LocalIP: "10.150.0.9", NetworkCIDR: "10.150.0.0/24",
		SearchDomain: "corp.mesh", Resolvers: []control.NativeDNSResolver{{IP: "10.150.0.2", Port: 5353}},
	}
}

func TestLinuxNativeDNSManagerReassertsIdempotentlyAndReverts(t *testing.T) {
	runner := &nativeDNSRecordingRunner{}
	proxy := &nativeDNSFakeProxy{port: 53001}
	starts := 0
	manager := &linuxNativeDNSManager{
		runner: runner,
		interfaceForIP: func(address netip.Addr) (string, error) {
			if address.String() != "10.150.0.9" {
				t.Fatalf("unexpected local address %s", address)
			}
			return "nebula1", nil
		},
		startProxy: func(control.NativeDNSPolicy) (nativeDNSProxyHandle, error) {
			starts++
			return proxy, nil
		},
	}
	config := nativeDNSSignedConfig(t, testNativeDNSPolicy())
	if err := manager.Reconcile(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"resolvectl", "dns", "nebula1", "10.150.0.9:53001"},
		{"resolvectl", "domain", "nebula1", "corp.mesh"},
		{"resolvectl", "default-route", "nebula1", "false"},
		{"resolvectl", "dnssec", "nebula1", "no"},
		{"resolvectl", "dnsovertls", "nebula1", "no"},
		{"resolvectl", "llmnr", "nebula1", "no"},
		{"resolvectl", "mdns", "nebula1", "no"},
	}
	if !reflect.DeepEqual(runner.commands, want) || starts != 1 || proxy.closed != 0 {
		t.Fatalf("apply commands=%#v starts=%d closed=%d", runner.commands, starts, proxy.closed)
	}
	if err := manager.Reconcile(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(runner.commands[len(want):], want) || starts != 1 {
		t.Fatal("unchanged signed policy did not reassert state without restarting the adapter")
	}
	if err := manager.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if proxy.closed != 1 || !reflect.DeepEqual(runner.commands[len(runner.commands)-1], []string{"resolvectl", "revert", "nebula1"}) {
		t.Fatalf("disable commands=%#v closed=%d", runner.commands, proxy.closed)
	}
	if err := manager.Disable(context.Background()); err != nil || len(runner.commands) != 2*len(want)+1 {
		t.Fatal("repeated disable was not write-free")
	}
}

func TestLinuxNativeDNSManagerRollsBackPartialResolverRegistration(t *testing.T) {
	runner := &nativeDNSRecordingRunner{failAt: 2}
	proxy := &nativeDNSFakeProxy{port: 53002}
	manager := &linuxNativeDNSManager{
		runner: runner, interfaceForIP: func(netip.Addr) (string, error) { return "nebula2", nil },
		startProxy: func(control.NativeDNSPolicy) (nativeDNSProxyHandle, error) { return proxy, nil },
	}
	err := manager.Reconcile(context.Background(), nativeDNSSignedConfig(t, testNativeDNSPolicy()))
	if err == nil || !strings.Contains(err.Error(), "configure native DNS domain") {
		t.Fatalf("partial apply returned %v", err)
	}
	if proxy.closed != 1 || manager.active != nil || !reflect.DeepEqual(runner.commands[len(runner.commands)-1], []string{"resolvectl", "revert", "nebula2"}) {
		t.Fatalf("partial apply did not rollback: commands=%#v proxy=%#v active=%#v", runner.commands, proxy, manager.active)
	}
}

func TestNativeDNSProxyRewritesSuffixAndFailsOver(t *testing.T) {
	upstream := startNativeDNSTestServer(t, func(request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		if len(request.Question) == 1 && request.Question[0].Name == "api." {
			record, err := dns.NewRR("api. 30 IN A 10.150.0.44")
			if err != nil {
				t.Fatal(err)
			}
			response.Answer = []dns.RR{record}
		} else {
			response.Rcode = dns.RcodeNameError
		}
		return response
	})
	unused, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	unusedAddress := unused.LocalAddr().String()
	_ = unused.Close()
	proxy := &nativeDNSProxy{
		localIP: netip.MustParseAddr("127.0.0.1"), domain: "corp.mesh",
		resolvers: []string{unusedAddress, upstream},
	}
	query := new(dns.Msg)
	query.SetQuestion("api.corp.mesh.", dns.TypeA)
	response, err := proxy.forward(query)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Answer) != 1 || response.Question[0].Name != "api.corp.mesh." || response.Answer[0].Header().Name != "api.corp.mesh." || response.Answer[0].String() != "api.corp.mesh.\t30\tIN\tA\t10.150.0.44" {
		t.Fatalf("unexpected translated response: %#v", response)
	}
	outside := new(dns.Msg)
	outside.SetQuestion("example.com.", dns.TypeA)
	if _, err := proxy.forward(outside); err == nil {
		t.Fatal("proxy accepted a query outside the signed search domain")
	}
}

func TestNativeDNSProxyRejectsUnrelatedUpstreamOwnersAndRemoteSources(t *testing.T) {
	upstream := startNativeDNSTestServer(t, func(request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		record, _ := dns.NewRR("other. 30 IN A 10.150.0.55")
		response.Answer = []dns.RR{record}
		return response
	})
	proxy := &nativeDNSProxy{localIP: netip.MustParseAddr("10.150.0.9"), domain: "corp.mesh", resolvers: []string{upstream}}
	query := new(dns.Msg)
	query.SetQuestion("api.corp.mesh.", dns.TypeA)
	if _, err := proxy.forward(query); err == nil {
		t.Fatal("proxy accepted an unrelated upstream owner")
	}
	if proxy.localSource(&net.UDPAddr{IP: net.ParseIP("10.150.0.10"), Port: 1234}) || !proxy.localSource(&net.UDPAddr{IP: net.ParseIP("10.150.0.9"), Port: 1234}) || !proxy.localSource(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}) {
		t.Fatal("native DNS local-source boundary was not enforced")
	}
}

func startNativeDNSTestServer(t *testing.T, answer func(*dns.Msg) *dns.Msg) string {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: listener, Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		_ = writer.WriteMsg(answer(request))
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return listener.LocalAddr().String()
}

// TestNativeDNSSmokeProcess is compiled into a disposable test binary by the
// Linux namespace harness. It runs the production adapter against a real
// signed bundle and real Nebula lighthouse resolver until the harness stops
// it. Ordinary unit runs always skip it.
func TestNativeDNSSmokeProcess(t *testing.T) {
	if os.Getenv("MESH_NATIVE_DNS_SMOKE_PROCESS") != "1" {
		t.Skip("namespace smoke helper")
	}
	configPath := os.Getenv("MESH_NATIVE_DNS_SIGNED_CONFIG")
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	policy, enabled, err := control.ParseNativeDNSPolicy(string(raw))
	if err != nil || !enabled {
		t.Fatalf("parse signed native DNS policy: enabled=%t err=%v", enabled, err)
	}
	proxy, err := startNativeDNSProxy(policy)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	fmt.Printf("MESH_NATIVE_DNS_READY=%s:%d\n", policy.LocalIP, proxy.Port())
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}
