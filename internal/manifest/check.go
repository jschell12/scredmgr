package manifest

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Verify performs a live API check: GET baseUrl+checkPath with the service's
// auth header. Returns an error on any non-2xx response (fail closed).
func Verify(svc *Service, token string) error {
	if svc.BaseURL == "" || svc.CheckPath == "" {
		return fmt.Errorf("service %q has no baseUrl/checkPath to verify against", svc.ID)
	}
	u := strings.TrimRight(svc.BaseURL, "/") + svc.CheckPath
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	name, value, err := BuildHeader(svc.AuthHeader, token)
	if err != nil {
		return err
	}
	req.Header.Set(name, value)
	req.Header.Set("User-Agent", "scredmanager")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("check %s: %w", svc.ID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("check %s: %s returned %s", svc.ID, u, resp.Status)
	}
	return nil
}

// SameHost reports whether rawURL's host matches the service's baseUrl host.
// Used by `scredmanager curl` as a hard allowlist.
func SameHost(svc *Service, rawURL string) (bool, error) {
	if svc.BaseURL == "" {
		return false, fmt.Errorf("service %q has no baseUrl; refusing to inject credentials", svc.ID)
	}
	base, err := url.Parse(svc.BaseURL)
	if err != nil {
		return false, err
	}
	target, err := url.Parse(rawURL)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(base.Hostname(), target.Hostname()), nil
}
