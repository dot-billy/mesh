package control

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	nebulacert "github.com/slackhq/nebula/cert"
)

func TestNormalizeRoutedSubnetsRejectsAmbiguousAndDangerousRanges(t *testing.T) {
	valid, err := normalizeRoutedSubnets([]string{"192.168.20.0/24", "10.20.0.0/16"})
	if err != nil || !slices.Equal(valid, []string{"10.20.0.0/16", "192.168.20.0/24"}) {
		t.Fatalf("normalized routed subnets=%v err=%v", valid, err)
	}
	for name, values := range map[string][]string{
		"noncanonical":     {"192.168.20.1/24"},
		"default":          {"0.0.0.0/1"},
		"loopback":         {"127.0.0.0/8"},
		"link local":       {"169.254.0.0/16"},
		"multicast":        {"224.0.0.0/4"},
		"duplicate":        {"192.168.20.0/24", "192.168.20.0/24"},
		"internal overlap": {"192.168.20.0/24", "192.168.20.128/25"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeRoutedSubnets(values); err == nil {
				t.Fatalf("accepted routed subnets %v", values)
			}
		})
	}
	overLimit := make([]string, maxRoutedSubnetsPerNode+1)
	for index := range overLimit {
		overLimit[index] = "198.51.100." + string(rune('0'+index)) + "/32"
	}
	if _, err := normalizeRoutedSubnets(overLimit); err == nil {
		t.Fatal("accepted too many routed subnets")
	}
}

func TestRoutedSubnetReservationsRejectLiveOverlapAndReleaseOnRevocation(t *testing.T) {
	service := testService(t)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "routes-a", CIDR: "10.60.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := service.CreateNode(network.ID, CreateNodeInput{Name: "gateway-a", RoutedSubnets: []string{"192.168.50.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(owner.Node.RoutedSubnets, []string{"192.168.50.0/24"}) {
		t.Fatalf("created owner routes=%v", owner.Node.RoutedSubnets)
	}
	for name, input := range map[string]CreateNodeInput{
		"managed overlay": {Name: "gateway-overlay", RoutedSubnets: []string{"10.60.0.0/25"}},
		"exact route":     {Name: "gateway-exact", RoutedSubnets: []string{"192.168.50.0/24"}},
		"contained route": {Name: "gateway-contained", RoutedSubnets: []string{"192.168.50.128/25"}},
		"covering route":  {Name: "gateway-covering", RoutedSubnets: []string{"192.168.0.0/16"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.CreateNode(network.ID, input); err == nil || !strings.Contains(err.Error(), "overlap") {
				t.Fatalf("overlap result err=%v", err)
			}
		})
	}
	second, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "routes-b", CIDR: "10.61.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateNode(second.ID, CreateNodeInput{Name: "gateway-cross-network", RoutedSubnets: []string{"192.168.50.0/25"}}); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("cross-network overlap err=%v", err)
	}
	if _, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "route-as-overlay", CIDR: "192.168.50.0/24"}); err == nil {
		t.Fatal("managed network was allowed to overlap a live routed subnet")
	}
	if _, err := service.RevokeNode(owner.Node.ID); err != nil {
		t.Fatal(err)
	}
	replacement, err := service.CreateNode(second.ID, CreateNodeInput{Name: "gateway-replacement", RoutedSubnets: []string{"192.168.50.0/24"}})
	if err != nil || !slices.Equal(replacement.Node.RoutedSubnets, owner.Node.RoutedSubnets) {
		t.Fatalf("revoked reservation was not reusable: node=%#v err=%v", replacement.Node, err)
	}
}

func TestRoutedSubnetEnrollmentBindsCertificateAndSignedConfigLifecycle(t *testing.T) {
	if _, err := exec.LookPath("nebula-cert"); err != nil {
		t.Skip("nebula-cert is not installed")
	}
	service := testService(t)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "routed-lifecycle", CIDR: "10.62.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := service.CreateNode(network.ID, CreateNodeInput{Name: "gateway", RoutedSubnets: []string{"172.20.40.0/24"}, Groups: []string{"routers"}})
	if err != nil {
		t.Fatal(err)
	}
	member, err := service.CreateNode(network.ID, CreateNodeInput{Name: "client"})
	if err != nil {
		t.Fatal(err)
	}

	gatewayPublicKey := generateRoutedTestPublicKey(t, "gateway")
	memberPublicKey := generateRoutedTestPublicKey(t, "member")
	gatewayToken := strings.Repeat("g", 42) + "A"
	memberToken := strings.Repeat("m", 42) + "A"
	gatewayBundle, err := service.Enroll(context.Background(), gateway.EnrollmentToken, gatewayPublicKey, HashToken(gatewayToken))
	if err != nil {
		t.Fatal(err)
	}
	certificate, remainder, err := nebulacert.UnmarshalCertificateFromPEM([]byte(gatewayBundle.Certificate))
	if err != nil || len(remainder) != 0 {
		t.Fatalf("parse gateway certificate: remainder=%q err=%v", remainder, err)
	}
	if got := certificate.UnsafeNetworks(); !slices.Equal(got, []netip.Prefix{netip.MustParsePrefix("172.20.40.0/24")}) {
		t.Fatalf("gateway certificate unsafe networks=%v", got)
	}
	if gatewayBundle.ConfigRevision != 2 {
		t.Fatalf("gateway activation revision=%d, want 2", gatewayBundle.ConfigRevision)
	}
	if strings.Contains(gatewayBundle.Config, "unsafe_routes:") || !strings.Contains(gatewayBundle.Config, "local_cidr: 172.20.40.0/24") {
		t.Fatalf("gateway config did not omit its own route and explicitly extend inbound policy:\n%s", gatewayBundle.Config)
	}

	memberBundle, err := service.Enroll(context.Background(), member.EnrollmentToken, memberPublicKey, HashToken(memberToken))
	if err != nil {
		t.Fatal(err)
	}
	wantRoute := "tun:\n  unsafe_routes:\n    - route: \"172.20.40.0/24\"\n      via: \"" + gateway.Node.IP + "\"\n"
	if !strings.Contains(memberBundle.Config, wantRoute) || strings.Contains(memberBundle.Config, "local_cidr: 172.20.40.0/24") {
		t.Fatalf("member config did not carry only the remote routed-subnet entry:\n%s", memberBundle.Config)
	}
	if err := VerifyConfig(memberBundle.ConfigSigningPublicKey, memberBundle.SignatureMetadata(), memberBundle.Config, memberBundle.ConfigSHA256, memberBundle.ConfigSignature); err != nil {
		t.Fatalf("verify member routed config: %v", err)
	}

	if _, err := service.RevokeNode(gateway.Node.ID); err != nil {
		t.Fatal(err)
	}
	afterRevocation, err := service.AgentConfig(memberToken)
	if err != nil {
		t.Fatal(err)
	}
	if afterRevocation.Revision != 3 || strings.Contains(afterRevocation.Config, "unsafe_routes:") || !strings.Contains(afterRevocation.Config, gatewayBundle.CertificateFingerprint) {
		t.Fatalf("revocation did not remove the route and blocklist its owner: revision=%d\n%s", afterRevocation.Revision, afterRevocation.Config)
	}
}

func generateRoutedTestPublicKey(t *testing.T, name string) string {
	t.Helper()
	directory := t.TempDir()
	keyPath := filepath.Join(directory, name+".key")
	publicPath := filepath.Join(directory, name+".pub")
	if output, err := exec.Command("nebula-cert", "keygen", "-out-key", keyPath, "-out-pub", publicPath).CombinedOutput(); err != nil {
		t.Fatalf("generate %s key: %v: %s", name, err, output)
	}
	publicKey, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(publicKey)
}
