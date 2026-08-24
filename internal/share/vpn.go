package share

import (
	"context"
	"regexp"
	"runtime"
	"strings"
)

// Runner executes an external command. Same contract as provider.Runner:
// secrets never on argv or in the child environment. VPN detection and host
// probing pass no secrets at all.
type Runner func(ctx context.Context, name string, args []string, stdin []byte) (stdout []byte, err error)

// VPNInfo describes detected VPN state on this machine.
type VPNInfo struct {
	Active bool
	// Names are connected VPN service names (macOS scutil), if any.
	Names []string
	// Interface is the default-route interface when it looks like a tunnel.
	Interface string
}

// Detail returns a human-readable one-liner for warnings.
func (v VPNInfo) Detail() string {
	var parts []string
	if len(v.Names) > 0 {
		parts = append(parts, strings.Join(v.Names, ", "))
	}
	if v.Interface != "" {
		parts = append(parts, "default route via "+v.Interface)
	}
	return strings.Join(parts, "; ")
}

var (
	darwinTunnelIface = regexp.MustCompile(`^(utun|ppp|ipsec|tun|tap)\d*$`)
	linuxTunnelIface  = regexp.MustCompile(`^(tun|tap|wg|tailscale|ppp)\d*$`)
	// scutil --nc list connected lines look like:
	// * (Connected)   ID PPP --> "My VPN" [PPP:L2TP]
	scutilConnected = regexp.MustCompile(`\(Connected\).*?"([^"]+)"`)
)

// DetectVPN reports whether a VPN appears active. Detection is best-effort:
// a command failure returns Active=false plus the error so callers can warn
// without blocking — only a *detected* VPN gates sharing.
func DetectVPN(ctx context.Context, run Runner) (VPNInfo, error) {
	switch runtime.GOOS {
	case "darwin":
		return detectVPNDarwin(ctx, run)
	default:
		return detectVPNLinux(ctx, run)
	}
}

func detectVPNDarwin(ctx context.Context, run Runner) (VPNInfo, error) {
	var info VPNInfo
	var firstErr error

	if out, err := run(ctx, "scutil", []string{"--nc", "list"}, nil); err != nil {
		firstErr = err
	} else {
		info.Names = ParseScutilNC(string(out))
	}
	if out, err := run(ctx, "route", []string{"-n", "get", "default"}, nil); err != nil {
		if firstErr == nil {
			firstErr = err
		}
	} else if iface := ParseRouteGetDefault(string(out)); darwinTunnelIface.MatchString(iface) {
		info.Interface = iface
	}
	info.Active = len(info.Names) > 0 || info.Interface != ""
	return info, firstErr
}

func detectVPNLinux(ctx context.Context, run Runner) (VPNInfo, error) {
	out, err := run(ctx, "ip", []string{"route", "show", "default"}, nil)
	if err != nil {
		return VPNInfo{}, err
	}
	var info VPNInfo
	if iface := ParseIPRouteDefault(string(out)); linuxTunnelIface.MatchString(iface) {
		info.Interface = iface
		info.Active = true
	}
	return info, nil
}

// ParseScutilNC extracts connected VPN service names from `scutil --nc list`
// output.
func ParseScutilNC(out string) []string {
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if m := scutilConnected.FindStringSubmatch(line); m != nil {
			names = append(names, m[1])
		}
	}
	return names
}

// ParseRouteGetDefault extracts the interface name from
// `route -n get default` output ("  interface: en0").
func ParseRouteGetDefault(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "interface:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// ParseIPRouteDefault extracts the device from `ip route show default`
// output ("default via 10.0.0.1 dev wg0 ..."). The first default route wins.
func ParseIPRouteDefault(out string) string {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				return fields[i+1]
			}
		}
	}
	return ""
}
