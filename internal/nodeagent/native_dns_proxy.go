package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"mesh/internal/control"
)

const (
	nativeDNSExchangeTimeout = 750 * time.Millisecond
	nativeDNSPacketSize      = 1232
)

type nativeDNSProxyHandle interface {
	Port() int
	Close() error
}

type nativeDNSProxy struct {
	localIP   netip.Addr
	domain    string
	resolvers []string
	server    *dns.Server
	conn      *net.UDPConn
	closeOnce sync.Once
	closeErr  error
}

func startNativeDNSProxy(policy control.NativeDNSPolicy) (nativeDNSProxyHandle, error) {
	return startNativeDNSProxyAtPort(policy, 0)
}

func startNativeDNSProxyAtPort(policy control.NativeDNSPolicy, port int) (nativeDNSProxyHandle, error) {
	localIP, err := netip.ParseAddr(policy.LocalIP)
	if err != nil || !localIP.Is4() {
		return nil, errors.New("native DNS local address is invalid")
	}
	if port < 0 || port > 65535 {
		return nil, errors.New("native DNS adapter port is invalid")
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(localIP.AsSlice()), Port: port})
	if err != nil {
		return nil, fmt.Errorf("listen on native DNS adapter: %w", err)
	}
	proxy := &nativeDNSProxy{localIP: localIP, domain: policy.SearchDomain, conn: listener}
	for _, resolver := range policy.Resolvers {
		proxy.resolvers = append(proxy.resolvers, net.JoinHostPort(resolver.IP, fmt.Sprintf("%d", resolver.Port)))
	}
	proxy.server = &dns.Server{
		PacketConn: listener, Handler: proxy,
		ReadTimeout: nativeDNSExchangeTimeout, WriteTimeout: nativeDNSExchangeTimeout,
		UDPSize: nativeDNSPacketSize,
	}
	go func() { _ = proxy.server.ActivateAndServe() }()
	return proxy, nil
}

func (p *nativeDNSProxy) Port() int {
	if p == nil || p.conn == nil {
		return 0
	}
	address, _ := p.conn.LocalAddr().(*net.UDPAddr)
	if address == nil {
		return 0
	}
	return address.Port
}

func (p *nativeDNSProxy) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		if p.server != nil {
			p.closeErr = p.server.Shutdown()
		} else if p.conn != nil {
			p.closeErr = p.conn.Close()
		}
	})
	return p.closeErr
}

func (p *nativeDNSProxy) ServeDNS(writer dns.ResponseWriter, request *dns.Msg) {
	if !p.localSource(writer.RemoteAddr()) {
		return
	}
	response, err := p.forward(request)
	if err != nil {
		failure := new(dns.Msg)
		failure.SetRcode(request, dns.RcodeServerFailure)
		failure.RecursionAvailable = false
		_ = writer.WriteMsg(failure)
		return
	}
	_ = writer.WriteMsg(response)
}

func (p *nativeDNSProxy) localSource(address net.Addr) bool {
	if address == nil {
		return false
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return false
	}
	source, err := netip.ParseAddr(host)
	return err == nil && (source.IsLoopback() || source == p.localIP)
}

func (p *nativeDNSProxy) forward(request *dns.Msg) (*dns.Msg, error) {
	if request == nil || request.Response || request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 || len(request.Answer) != 0 || len(request.Ns) != 0 {
		return nil, errors.New("native DNS query shape is invalid")
	}
	question := request.Question[0]
	if question.Qclass != dns.ClassINET {
		return nil, errors.New("native DNS query class is unsupported")
	}
	originalName := question.Name
	lowerName := strings.ToLower(originalName)
	suffix := "." + p.domain + "."
	if !strings.HasSuffix(lowerName, suffix) || len(lowerName) <= len(suffix) {
		return nil, errors.New("native DNS query is outside the signed search domain")
	}
	bareName := strings.TrimSuffix(lowerName, suffix) + "."
	if _, ok := dns.IsDomainName(bareName); !ok {
		return nil, errors.New("native DNS query name is invalid")
	}
	query := new(dns.Msg)
	query.MsgHdr = request.MsgHdr
	query.Response = false
	query.RecursionDesired = false
	query.CheckingDisabled = false
	query.Question = []dns.Question{{Name: bareName, Qtype: question.Qtype, Qclass: question.Qclass}}
	client := &dns.Client{Net: "udp", Timeout: nativeDNSExchangeTimeout, UDPSize: nativeDNSPacketSize}
	var lastErr error
	for _, resolver := range p.resolvers {
		ctx, cancel := context.WithTimeout(context.Background(), nativeDNSExchangeTimeout)
		response, _, err := client.ExchangeContext(ctx, query, resolver)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		if err := validateNativeDNSResponse(query, response, bareName); err != nil {
			lastErr = err
			continue
		}
		response.Id = request.Id
		response.Question[0].Name = originalName
		for _, section := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
			for _, record := range section {
				record.Header().Name = originalName
			}
		}
		response.RecursionAvailable = false
		return response, nil
	}
	if lastErr == nil {
		lastErr = errors.New("signed native DNS resolver inventory is empty")
	}
	return nil, lastErr
}

func validateNativeDNSResponse(query, response *dns.Msg, bareName string) error {
	if response == nil || !response.Response || response.Opcode != dns.OpcodeQuery || response.Id != query.Id || len(response.Question) != 1 {
		return errors.New("native DNS upstream response header is invalid")
	}
	question := response.Question[0]
	if strings.ToLower(question.Name) != bareName || question.Qtype != query.Question[0].Qtype || question.Qclass != query.Question[0].Qclass {
		return errors.New("native DNS upstream response question does not match")
	}
	for _, section := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range section {
			if record == nil || strings.ToLower(record.Header().Name) != bareName {
				return errors.New("native DNS upstream response contains an unrelated owner")
			}
		}
	}
	return nil
}
