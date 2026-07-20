package loginflow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunDeviceFlow(t *testing.T) {
	var polls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/device/code", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("client_id") != "cid" {
			t.Errorf("client_id = %q", r.FormValue("client_id"))
		}
		if r.FormValue("scope") != "repo" {
			t.Errorf("scope = %q", r.FormValue("scope"))
		}
		json.NewEncoder(w).Encode(map[string]any{
			"device_code":      "dev123",
			"user_code":        "ABCD-1234",
			"verification_uri": "https://example.com/device",
			"expires_in":       60,
			"interval":         0, // test speed; defaults handled below
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("device_code") != "dev123" {
			t.Errorf("device_code = %q", r.FormValue("device_code"))
		}
		if polls.Add(1) < 3 {
			json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"access_token": "tok_success"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var promptedCode string
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// interval=0 in the response falls back to 5s — too slow for a unit test,
	// so shrink via a tiny expires_in? Instead patch: use a custom config with
	// the flow's default minimum. To keep the test fast we accept the first
	// poll happening after the fallback interval would stall; so override by
	// running with a canceled-on-success context and short interval response.
	token, err := runDeviceFlowWithInterval(ctx, DeviceFlowConfig{
		ClientID:      "cid",
		Scope:         "repo",
		DeviceAuthURL: srv.URL + "/device/code",
		TokenURL:      srv.URL + "/token",
	}, func(userCode, uri string) { promptedCode = userCode }, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if token != "tok_success" {
		t.Fatalf("token = %q", token)
	}
	if promptedCode != "ABCD-1234" {
		t.Fatalf("prompted code = %q", promptedCode)
	}
	if polls.Load() != 3 {
		t.Fatalf("polls = %d, want 3", polls.Load())
	}
}

func TestRunDeviceFlowDenied(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/device/code", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"device_code": "d", "user_code": "u", "verification_uri": "v", "expires_in": 60, "interval": 0,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "access_denied"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := runDeviceFlowWithInterval(context.Background(), DeviceFlowConfig{
		ClientID: "cid", DeviceAuthURL: srv.URL + "/device/code", TokenURL: srv.URL + "/token",
	}, func(string, string) {}, 10*time.Millisecond)
	if err == nil {
		t.Fatal("want access_denied error")
	}
}

func TestRunDeviceFlowRequiresClientID(t *testing.T) {
	if _, err := RunDeviceFlow(context.Background(), DeviceFlowConfig{}, nil); err == nil {
		t.Fatal("want error for missing clientId")
	}
}
