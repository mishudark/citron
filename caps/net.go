package caps

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
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
	hostSet := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}
	n := &netImpl{
		hosts: hostSet,
		valid: true,
	}
	defer func() { n.valid = false }()
	return op(n)
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

func HTTPGet(netw Network, url string) (string, error) {
	n, ok := netw.(*netImpl)
	if !ok {
		return "", fmt.Errorf("cap: invalid Network")
	}
	host, err := extractHost(url)
	if err != nil {
		return "", err
	}
	if err := n.validate(host); err != nil {
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
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("cap: HTTP GET %q failed: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("cap: reading response body: %w", err)
	}
	return string(body), nil
}

func HTTPPost(netw Network, url, body, contentType string) (string, error) {
	n, ok := netw.(*netImpl)
	if !ok {
		return "", fmt.Errorf("cap: invalid Network")
	}
	host, err := extractHost(url)
	if err != nil {
		return "", err
	}
	if err := n.validate(host); err != nil {
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
		return "", fmt.Errorf("cap: HTTP POST %q failed: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("cap: reading response body: %w", err)
	}
	return string(respBody), nil
}
