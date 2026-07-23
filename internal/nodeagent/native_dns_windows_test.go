//go:build windows

package nodeagent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"mesh/internal/control"

	"golang.org/x/sys/windows"
)

func TestWindowsNativeDNSNRPTLifecycle(t *testing.T) {
	if os.Getenv("MESH_WINDOWS_NATIVE_DNS_TEST") != "1" {
		t.Skip("set MESH_WINDOWS_NATIVE_DNS_TEST=1 on an isolated elevated Windows host")
	}
	token := windows.GetCurrentProcessToken()
	if !token.IsElevated() {
		t.Fatal("native Windows NRPT proof requires an elevated token")
	}
	localIP, err := netip.ParseAddr(os.Getenv("MESH_WINDOWS_NATIVE_DNS_LOCAL_IP"))
	if err != nil || !localIP.Is4() || localIP.IsLoopback() || localIP.IsUnspecified() || localIP.String() != os.Getenv("MESH_WINDOWS_NATIVE_DNS_LOCAL_IP") {
		t.Fatal("MESH_WINDOWS_NATIVE_DNS_LOCAL_IP must be one canonical non-loopback IPv4 address assigned to this host")
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(localIP.AsSlice())})
	if err != nil {
		t.Fatalf("listen on native Windows DNS proof upstream: %v", err)
	}
	upstreamPort := listener.LocalAddr().(*net.UDPAddr).Port
	upstream := &dns.Server{
		PacketConn: listener,
		Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
			if request == nil || len(request.Question) != 1 || strings.ToLower(request.Question[0].Name) != "mesh-native-proof." {
				return
			}
			response := new(dns.Msg)
			response.SetReply(request)
			response.Authoritative = true
			response.RecursionAvailable = false
			if request.Question[0].Qtype == dns.TypeA {
				response.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5},
					A:   net.IP(localIP.AsSlice()),
				}}
			}
			_ = writer.WriteMsg(response)
		}),
		ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second,
	}
	go func() { _ = upstream.ActivateAndServe() }()
	t.Cleanup(func() { _ = upstream.Shutdown() })

	policy := control.NativeDNSPolicy{
		Schema: control.NativeDNSPolicySchema, LocalIP: localIP.String(), NetworkCIDR: localIP.String() + "/32",
		SearchDomain: "mesh-native-test.invalid",
		Resolvers:    []control.NativeDNSResolver{{IP: localIP.String(), Port: upstreamPort}},
	}
	raw, err := jsonMarshalNativeDNSPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewNativeDNSManager(ExecCommandRunner{})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := manager.Disable(ctx); err != nil {
			t.Errorf("cleanup native Windows DNS: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := manager.Reconcile(ctx, raw); err != nil {
		t.Fatalf("activate native Windows NRPT policy: %v", err)
	}
	lookupCtx, lookupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	addresses, err := net.DefaultResolver.LookupHost(lookupCtx, "mesh-native-proof.mesh-native-test.invalid")
	lookupCancel()
	if err != nil {
		t.Fatalf("resolve through native Windows NRPT policy: %v", err)
	}
	found := false
	for _, address := range addresses {
		if address == localIP.String() {
			found = true
		}
	}
	if !found {
		t.Fatalf("native Windows NRPT answer = %v, want %s", addresses, localIP)
	}
	if err := manager.Disable(ctx); err != nil {
		t.Fatalf("disable native Windows NRPT policy: %v", err)
	}
	concrete, ok := manager.(*windowsNativeDNSManager)
	if !ok {
		t.Fatal("Windows native DNS constructor returned an unexpected implementation")
	}
	snapshot, err := concrete.backend.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := ownedWindowsNRPTRules(snapshot.Configured)
	if err != nil || len(owned) != 0 {
		t.Fatalf("native Windows NRPT cleanup leaves %d Mesh rules: %v", len(owned), err)
	}
}

func jsonMarshalNativeDNSPolicy(policy control.NativeDNSPolicy) (string, error) {
	raw, err := json.Marshal(policy)
	if err != nil {
		return "", err
	}
	if len(raw) == 0 {
		return "", fmt.Errorf("native DNS policy is empty")
	}
	return control.NativeDNSPolicyPrefix + base64.RawURLEncoding.EncodeToString(raw) + "\npki:\n", nil
}
