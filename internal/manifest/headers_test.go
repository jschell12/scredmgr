package manifest

import "testing"

func TestBuildHeader(t *testing.T) {
	cases := []struct {
		spec, token, wantName, wantValue string
		wantErr                          bool
	}{
		{"bearer", "t", "Authorization", "Bearer t", false},
		{"", "t", "Authorization", "Bearer t", false},
		{"basic:user", "t", "Authorization", "Basic dXNlcjp0", false},
		{"token=", "t", "Authorization", "Token token=t", false},
		{"private-token", "t", "PRIVATE-TOKEN", "t", false},
		{"header:X-Api-Key", "t", "X-Api-Key", "t", false},
		{"basic:", "t", "", "", true},
		{"header:", "t", "", "", true},
		{"nonsense", "t", "", "", true},
	}
	for _, c := range cases {
		name, value, err := BuildHeader(c.spec, c.token)
		if c.wantErr {
			if err == nil {
				t.Errorf("BuildHeader(%q): want error", c.spec)
			}
			continue
		}
		if err != nil || name != c.wantName || value != c.wantValue {
			t.Errorf("BuildHeader(%q) = %q, %q, %v; want %q, %q", c.spec, name, value, err, c.wantName, c.wantValue)
		}
	}
}

func TestSameHost(t *testing.T) {
	svc := &Service{ID: "jira", BaseURL: "https://example.atlassian.net"}
	ok, err := SameHost(svc, "https://example.atlassian.net/rest/api/2/myself")
	if err != nil || !ok {
		t.Fatalf("same host rejected: %v %v", ok, err)
	}
	ok, err = SameHost(svc, "https://evil.example.com/steal")
	if err != nil || ok {
		t.Fatalf("cross-host allowed: %v %v", ok, err)
	}
	if _, err := SameHost(&Service{ID: "x"}, "https://a.com"); err == nil {
		t.Fatal("missing baseUrl must refuse")
	}
}
