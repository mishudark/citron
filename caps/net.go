package caps

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

// maxResponseBytes bounds the response body any HTTP capability call will
// buffer, preventing memory exhaustion from an allowlisted host.
const maxResponseBytes = 10 << 20 // 10 MiB

type Network interface {
	Capability
}

type netImpl struct {
	capabilityMarker
	hosts map[string]bool
	valid atomic.Bool
}

func RequestNetwork[T any](
	hosts []string,
	op func(Network) (T, error),
) (T, error) {
	_, span := StartSpan(context.Background(), "caps.Network.Request",
		attribute.StringSlice("hosts", hosts),
	)
	defer EndSpan(span, nil)
	RecordRequest(context.Background(), "network")

	hostSet := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}
	n := &netImpl{hosts: hostSet}
	n.valid.Store(true)
	defer func() { n.valid.Store(false) }()
	result, err := op(n)
	EndSpan(span, err)
	return result, err
}

func (n *netImpl) validate(host string) error {
	if !n.valid.Load() {
		return fmt.Errorf("cap: Network used outside its scope")
	}
	if len(n.hosts) == 0 {
		return fmt.Errorf("cap: no network hosts permitted")
	}
	if !n.hosts[host] {
		allowed := make([]string, 0, len(n.hosts))
		for h := range n.hosts {
			allowed = append(allowed, h)
		}
		return fmt.Errorf("cap: host %q not in allowlist %v", host, allowed)
	}
	return nil
}

func extractHost(rawURL string) (host string, port string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", fmt.Errorf("cap: invalid URL %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", fmt.Errorf("cap: unsupported protocol in URL %q", rawURL)
	}
	host = u.Hostname()
	if host == "" {
		return "", "", fmt.Errorf("cap: empty host in URL %q", rawURL)
	}
	port = u.Port()
	return host, port, nil
}

// validatePort enforces default ports (80 for http, 443 for https); the
// allowlist is hostname-scoped, so allowing arbitrary ports would let a
// script reach any service on an allowed host.
func validatePort(port, scheme string) error {
	if port == "" {
		return nil
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return nil
	}
	return fmt.Errorf("cap: non-default port %q not permitted (allowlist is host-scoped)", port)
}

// isBlockedIP reports whether ip is in a range that must never be dialed when
// the allowlisted host is a domain name; this blocks DNS rebinding attacks
// that redirect an allowlisted domain to internal addresses. IP-literal
// allowlist entries opt into local addresses explicitly.
func isBlockedIP(ip net.IP) bool {
	return ip == nil ||
		ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified()
}

// pinningTransport returns an http.Transport whose dialer resolves the host
// itself, refuses private/reserved addresses for domain-name hosts, and dials
// the vetted IP directly; TLS SNI and the Host header still use the original
// hostname, so the connection stays valid for the allowlisted name.
func pinningTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			hostPort, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("cap: bad dial address %q: %w", addr, err)
			}
			if ip := net.ParseIP(hostPort); ip != nil {
				return dialer.DialContext(ctx, network, addr)
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostPort)
			if err != nil {
				return nil, fmt.Errorf("cap: resolving %q: %w", hostPort, err)
			}
			var lastErr error
			dialed := false
			for _, ia := range ips {
				if isBlockedIP(ia.IP) {
					return nil, fmt.Errorf("cap: host %q resolves to disallowed address %s", hostPort, ia.IP)
				}
				conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(ia.IP.String(), port))
				if derr == nil {
					return conn, nil
				}
				lastErr, dialed = derr, true
			}
			if !dialed {
				lastErr = fmt.Errorf("cap: no dialable addresses for %q", hostPort)
			}
			return nil, lastErr
		},
	}
}

func redirectValidator(n *netImpl) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("cap: too many redirects")
		}
		redirectHost, redirectPort, err := extractHost(req.URL.String())
		if err != nil {
			return fmt.Errorf("cap: invalid redirect URL: %w", err)
		}
		if err := validatePort(redirectPort, req.URL.Scheme); err != nil {
			return err
		}
		if err := n.validate(redirectHost); err != nil {
			return err
		}
		return nil
	}
}

func drainBody(resp *http.Response) (string, error) {
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("cap: reading response body: %w", err)
	}
	if int64(len(body)) > maxResponseBytes {
		return "", fmt.Errorf("cap: response body exceeds %d bytes", int64(maxResponseBytes))
	}
	return string(body), nil
}

func HTTPGet(netw Network, urlStr string) (string, error) {
	_, span := StartSpan(context.Background(), "caps.Network.HTTPGet",
		attribute.String("url", urlStr),
	)
	defer EndSpan(span, nil)

	n, ok := netw.(*netImpl)
	if !ok {
		RecordOperation(context.Background(), "http_get", fmt.Errorf("cap: invalid Network"))
		return "", fmt.Errorf("cap: invalid Network")
	}
	host, port, err := extractHost(urlStr)
	if err != nil {
		RecordOperation(context.Background(), "http_get", err)
		return "", err
	}
	if err := validatePort(port, schemeOf(urlStr)); err != nil {
		RecordOperation(context.Background(), "http_get", err)
		return "", err
	}
	if err := n.validate(host); err != nil {
		RecordOperation(context.Background(), "http_get", err)
		return "", err
	}
	client := &http.Client{
		Timeout:       30 * time.Second,
		Transport:     pinningTransport(),
		CheckRedirect: redirectValidator(n),
	}
	resp, err := client.Get(urlStr)
	if err != nil {
		RecordOperation(context.Background(), "http_get", err)
		return "", fmt.Errorf("cap: HTTP GET %q failed: %w", urlStr, err)
	}
	body, err := drainBody(resp)
	if err != nil {
		RecordOperation(context.Background(), "http_get", err)
		return "", err
	}
	RecordOperation(context.Background(), "http_get", nil)
	return body, nil
}

func HTTPPost(netw Network, url, body, contentType string) (string, error) {
	_, span := StartSpan(context.Background(), "caps.Network.HTTPPost",
		attribute.String("url", url),
		attribute.String("content_type", contentType),
	)
	defer EndSpan(span, nil)

	n, ok := netw.(*netImpl)
	if !ok {
		RecordOperation(context.Background(), "http_post", fmt.Errorf("cap: invalid Network"))
		return "", fmt.Errorf("cap: invalid Network")
	}
	host, port, err := extractHost(url)
	if err != nil {
		RecordOperation(context.Background(), "http_post", err)
		return "", err
	}
	if err := validatePort(port, schemeOf(url)); err != nil {
		RecordOperation(context.Background(), "http_post", err)
		return "", err
	}
	if err := n.validate(host); err != nil {
		RecordOperation(context.Background(), "http_post", err)
		return "", err
	}
	if contentType == "" {
		contentType = "application/json"
	}
	client := &http.Client{
		Timeout:       30 * time.Second,
		Transport:     pinningTransport(),
		CheckRedirect: redirectValidator(n),
	}
	resp, err := client.Post(url, contentType, strings.NewReader(body))
	if err != nil {
		RecordOperation(context.Background(), "http_post", err)
		return "", fmt.Errorf("cap: HTTP POST %q failed: %w", url, err)
	}
	respBody, err := drainBody(resp)
	if err != nil {
		RecordOperation(context.Background(), "http_post", err)
		return "", err
	}
	RecordOperation(context.Background(), "http_post", nil)
	return respBody, nil
}

// HTTPGetClassified fetches a URL and wraps the response body in Classified,
// for endpoints known to return sensitive data (metadata services, token
// endpoints, ...). The body never enters the agent context in plain form.
func HTTPGetClassified(netw Network, urlStr string) (Classified[string], error) {
	body, err := HTTPGet(netw, urlStr)
	RecordAudit("http_get_classified", urlStr, err)
	if err != nil {
		return Classified[string]{}, err
	}
	return Classify(body), nil
}

// HTTPPostClassified sends a Classified body to an allowlisted URL and
// returns the response wrapped in Classified. It is the only way to send
// classified data over the network: the body is accepted exclusively as a
// Classified value, so plain call sites can never carry secrets.
func HTTPPostClassified(netw Network, url string, body Classified[string], contentType string) (Classified[string], error) {
	respBody, err := HTTPPost(netw, url, body.value, contentType)
	RecordAudit("http_post_classified", url, err)
	if err != nil {
		return Classified[string]{}, err
	}
	return Classify(respBody), nil
}

func schemeOf(rawURL string) string {
	if i := strings.Index(rawURL, "://"); i > 0 {
		return rawURL[:i]
	}
	return ""
}
