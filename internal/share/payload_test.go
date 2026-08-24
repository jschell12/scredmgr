package share

import (
	"bytes"
	"strings"
	"testing"
)

func TestPayloadRoundTrip(t *testing.T) {
	p := &Payload{
		Version: Version,
		From:    "macbook",
		SentAt:  "2026-08-24T12:00:00Z",
		Entries: []Entry{{ID: "jira", SecretB64: "c2VjcmV0", EnvVar: "JIRA_TOKEN"}},
	}
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if got.From != "macbook" || len(got.Entries) != 1 || got.Entries[0].ID != "jira" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := map[string]string{
		"wrong version": `{"version":99,"from":"x","entries":[{"id":"a","secretB64":"eA=="}]}`,
		"no entries":    `{"version":1,"from":"x","entries":[]}`,
		"missing id":    `{"version":1,"from":"x","entries":[{"secretB64":"eA=="}]}`,
		"not json":      `hello`,
	}
	for name, in := range cases {
		if _, err := Decode(strings.NewReader(in)); err == nil {
			t.Fatalf("%s: Decode accepted %q", name, in)
		}
	}
}

func TestEncodeRejectsEmpty(t *testing.T) {
	if _, err := (&Payload{Version: Version}).Encode(); err == nil {
		t.Fatal("Encode accepted empty payload")
	}
}
