package share

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseSSHConfigHosts(t *testing.T) {
	cfg := `
# personal machines
Host mac-mini
  HostName 10.0.0.10
  User joshschell

Host framework fw
  HostName 10.0.0.2

Host *.internal !bad *
  User nobody

Match host something
  User other

host lowercase-directive
  HostName 1.2.3.4

Host mac-mini
  Port 22
`
	got := ParseSSHConfigHosts(strings.NewReader(cfg))
	want := []string{"mac-mini", "framework", "fw", "lowercase-directive"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseSSHConfigHosts = %v, want %v", got, want)
	}
}

func TestParseSSHConfigHostsEmpty(t *testing.T) {
	if got := ParseSSHConfigHosts(strings.NewReader("")); len(got) != 0 {
		t.Fatalf("empty config: %v", got)
	}
}
