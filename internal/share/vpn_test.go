package share

import (
	"context"
	"errors"
	"runtime"
	"testing"
)

const scutilNoVPN = `Available network connection services in the current set (*=enabled):
* (Disconnected)   1A2B3C4D-0000-0000-0000-000000000000 PPP --> "Work VPN" [PPP:L2TP]
`

const scutilConnectedVPN = `Available network connection services in the current set (*=enabled):
* (Connected)      1A2B3C4D-0000-0000-0000-000000000000 PPP --> "Work VPN" [PPP:L2TP]
* (Disconnected)   5E6F7A8B-0000-0000-0000-000000000000 IPSec --> "Other VPN" [IPSec]
`

const routeDefaultEn0 = `   route to: default
destination: default
       mask: default
    gateway: 10.0.0.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`

const routeDefaultUtun = `   route to: default
destination: default
    gateway: 100.64.0.1
  interface: utun4
      flags: <UP,GATEWAY,DONE,STATIC>
`

func TestParseScutilNC(t *testing.T) {
	if names := ParseScutilNC(scutilNoVPN); len(names) != 0 {
		t.Fatalf("no-VPN output parsed as connected: %v", names)
	}
	names := ParseScutilNC(scutilConnectedVPN)
	if len(names) != 1 || names[0] != "Work VPN" {
		t.Fatalf("ParseScutilNC = %v, want [Work VPN]", names)
	}
}

func TestParseRouteGetDefault(t *testing.T) {
	if got := ParseRouteGetDefault(routeDefaultEn0); got != "en0" {
		t.Fatalf("got %q, want en0", got)
	}
	if got := ParseRouteGetDefault(routeDefaultUtun); got != "utun4" {
		t.Fatalf("got %q, want utun4", got)
	}
}

func TestParseIPRouteDefault(t *testing.T) {
	cases := map[string]string{
		"default via 10.0.0.1 dev eth0 proto dhcp metric 100":  "eth0",
		"default via 100.64.0.1 dev wg0 metric 50":             "wg0",
		"default dev tailscale0 table 52 scope link":           "tailscale0",
		"": "",
	}
	for in, want := range cases {
		if got := ParseIPRouteDefault(in); got != want {
			t.Fatalf("ParseIPRouteDefault(%q) = %q, want %q", in, got, want)
		}
	}
}

func fakeRunner(outputs map[string]string, fail map[string]error) Runner {
	return func(_ context.Context, name string, args []string, _ []byte) ([]byte, error) {
		if err, ok := fail[name]; ok {
			return nil, err
		}
		return []byte(outputs[name]), nil
	}
}

func TestDetectVPNDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only paths")
	}
	// No VPN.
	info, err := DetectVPN(context.Background(), fakeRunner(map[string]string{
		"scutil": scutilNoVPN, "route": routeDefaultEn0}, nil))
	if err != nil || info.Active {
		t.Fatalf("clean network detected as VPN: %+v, %v", info, err)
	}
	// scutil-connected VPN.
	info, _ = DetectVPN(context.Background(), fakeRunner(map[string]string{
		"scutil": scutilConnectedVPN, "route": routeDefaultEn0}, nil))
	if !info.Active || len(info.Names) != 1 {
		t.Fatalf("connected VPN not detected: %+v", info)
	}
	// utun default route (WireGuard/Tailscale style, no scutil service).
	info, _ = DetectVPN(context.Background(), fakeRunner(map[string]string{
		"scutil": scutilNoVPN, "route": routeDefaultUtun}, nil))
	if !info.Active || info.Interface != "utun4" {
		t.Fatalf("utun default route not detected: %+v", info)
	}
	// Detection failure: not active, error surfaced.
	info, err = DetectVPN(context.Background(), fakeRunner(nil,
		map[string]error{"scutil": errors.New("boom"), "route": errors.New("boom")}))
	if info.Active || err == nil {
		t.Fatalf("failed detection should be inactive+error: %+v, %v", info, err)
	}
}
