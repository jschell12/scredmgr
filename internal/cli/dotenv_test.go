package cli

import "testing"

func TestParseDotenv(t *testing.T) {
	content := `
# comment
export JIRA_TOKEN=abc123
GITHUB_TOKEN="ghp_quoted"
export SINGLE='single quoted'
PLAIN=value # trailing comment
`
	pairs, err := parseDotenv(content)
	if err != nil {
		t.Fatal(err)
	}
	want := [][2]string{
		{"JIRA_TOKEN", "abc123"},
		{"GITHUB_TOKEN", "ghp_quoted"},
		{"SINGLE", "single quoted"},
		{"PLAIN", "value"},
	}
	if len(pairs) != len(want) {
		t.Fatalf("got %d pairs, want %d: %v", len(pairs), len(want), pairs)
	}
	for i := range want {
		if pairs[i] != want[i] {
			t.Errorf("pair %d = %v, want %v", i, pairs[i], want[i])
		}
	}
}

func TestParseDotenvErrors(t *testing.T) {
	if _, err := parseDotenv("NOEQUALS"); err == nil {
		t.Fatal("want error for missing =")
	}
	if _, err := parseDotenv("1BAD=x"); err == nil {
		t.Fatal("want error for invalid key")
	}
}

func TestParseDotenvValueWithEquals(t *testing.T) {
	pairs, err := parseDotenv("KEY=a=b=c")
	if err != nil || pairs[0][1] != "a=b=c" {
		t.Fatalf("got %v, %v", pairs, err)
	}
}
