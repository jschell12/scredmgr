package loginflow

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GitHub's public endpoints — the defaults when a manifest deviceFlow entry
// omits them.
const (
	DefaultDeviceAuthURL = "https://github.com/login/device/code"
	DefaultTokenURL      = "https://github.com/login/oauth/access_token"
)

// DeviceFlowConfig configures an OAuth 2.0 device authorization grant
// (RFC 8628). Pure API — no browser automation.
type DeviceFlowConfig struct {
	ClientID      string
	Scope         string
	DeviceAuthURL string
	TokenURL      string
}

type deviceAuthResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// RunDeviceFlow executes the device-code flow: request a user code, hand it
// to prompt (which shows it to the user and typically opens the verification
// URI), then poll until the user approves. Returns the access token.
func RunDeviceFlow(ctx context.Context, cfg DeviceFlowConfig, prompt func(userCode, verificationURI string)) (string, error) {
	return runDeviceFlowWithInterval(ctx, cfg, prompt, 0)
}

// runDeviceFlowWithInterval allows tests to override the poll interval;
// intervalOverride <= 0 uses the provider's interval (fallback 5s).
func runDeviceFlowWithInterval(ctx context.Context, cfg DeviceFlowConfig, prompt func(userCode, verificationURI string), intervalOverride time.Duration) (string, error) {
	if cfg.ClientID == "" {
		return "", fmt.Errorf("device flow: clientId is required")
	}
	if cfg.DeviceAuthURL == "" {
		cfg.DeviceAuthURL = DefaultDeviceAuthURL
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = DefaultTokenURL
	}
	client := &http.Client{Timeout: 30 * time.Second}

	form := url.Values{"client_id": {cfg.ClientID}}
	if cfg.Scope != "" {
		form.Set("scope", cfg.Scope)
	}
	var auth deviceAuthResponse
	if err := postForm(ctx, client, cfg.DeviceAuthURL, form, &auth); err != nil {
		return "", fmt.Errorf("device flow: code request: %w", err)
	}
	if auth.DeviceCode == "" || auth.UserCode == "" {
		return "", fmt.Errorf("device flow: provider returned no device/user code")
	}

	prompt(auth.UserCode, auth.VerificationURI)

	interval := time.Duration(auth.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if intervalOverride > 0 {
		interval = intervalOverride
	}
	deadline := time.Now().Add(time.Duration(auth.ExpiresIn) * time.Second)
	if auth.ExpiresIn <= 0 {
		deadline = time.Now().Add(15 * time.Minute)
	}

	pollForm := url.Values{
		"client_id":   {cfg.ClientID},
		"device_code": {auth.DeviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(interval):
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("device flow: code expired before approval")
		}
		var tok tokenResponse
		if err := postForm(ctx, client, cfg.TokenURL, pollForm, &tok); err != nil {
			return "", fmt.Errorf("device flow: token poll: %w", err)
		}
		switch tok.Error {
		case "":
			if tok.AccessToken != "" {
				return tok.AccessToken, nil
			}
			return "", fmt.Errorf("device flow: empty token response")
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		default:
			return "", fmt.Errorf("device flow: %s: %s", tok.Error, tok.ErrorDesc)
		}
	}
}

func postForm(ctx context.Context, client *http.Client, u string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// OAuth errors (authorization_pending etc.) come back 4xx from some
		// providers; try to decode before failing on status alone.
		if json.Unmarshal(body, out) == nil {
			return nil
		}
		return fmt.Errorf("%s returned %s", u, resp.Status)
	}
	return json.Unmarshal(body, out)
}
