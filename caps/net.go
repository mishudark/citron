package caps

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

type Network interface {
	Capability
}

type netImpl struct {
	capabilityMarker
	hosts map[string]bool
	valid bool
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
	n := &netImpl{
		hosts: hostSet,
		valid: true,
	}
	defer func() { n.valid = false }()
	result, err := op(n)
	EndSpan(span, err)
	return result, err
}

func (n *netImpl) validate(host string) error {
	if !n.valid {
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

func extractHost(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("cap: invalid URL %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("cap: unsupported protocol in URL %q", rawURL)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("cap: empty host in URL %q", rawURL)
	}
	return host, nil
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
	host, err := extractHost(urlStr)
	if err != nil {
		RecordOperation(context.Background(), "http_get", err)
		return "", err
	}
	if err := n.validate(host); err != nil {
		RecordOperation(context.Background(), "http_get", err)
		return "", err
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("cap: too many redirects")
			}
			redirectHost, err := extractHost(req.URL.String())
			if err != nil {
				return fmt.Errorf("cap: invalid redirect URL: %w", err)
			}
			if err := n.validate(redirectHost); err != nil {
				return err
			}
			return nil
		},
	}
	resp, err := client.Get(urlStr)
	if err != nil {
		RecordOperation(context.Background(), "http_get", err)
		return "", fmt.Errorf("cap: HTTP GET %q failed: %w", urlStr, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		RecordOperation(context.Background(), "http_get", err)
		return "", fmt.Errorf("cap: reading response body: %w", err)
	}
	RecordOperation(context.Background(), "http_get", nil)
	return string(body), nil
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
	host, err := extractHost(url)
	if err != nil {
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
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("cap: too many redirects")
			}
			redirectHost, err := extractHost(req.URL.String())
			if err != nil {
				return fmt.Errorf("cap: invalid redirect URL: %w", err)
			}
			if err := n.validate(redirectHost); err != nil {
				return err
			}
			return nil
		},
	}
	resp, err := client.Post(url, contentType, strings.NewReader(body))
	if err != nil {
		RecordOperation(context.Background(), "http_post", err)
		return "", fmt.Errorf("cap: HTTP POST %q failed: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		RecordOperation(context.Background(), "http_post", err)
		return "", fmt.Errorf("cap: reading response body: %w", err)
	}
	RecordOperation(context.Background(), "http_post", nil)
	return string(respBody), nil
}
