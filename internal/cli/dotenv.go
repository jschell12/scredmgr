package cli

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
)

var dotenvKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// parseDotenv parses `export KEY=value` / `KEY=value` lines. Values may be
// single- or double-quoted. Comments and blank lines are skipped. Returned
// order matches file order.
func parseDotenv(content string) ([][2]string, error) {
	var pairs [][2]string
	sc := bufio.NewScanner(strings.NewReader(content))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		line = strings.TrimSpace(line)
		eq := strings.Index(line, "=")
		if eq < 0 {
			return nil, fmt.Errorf("line %d: no '=' found", lineNo)
		}
		key := strings.TrimSpace(line[:eq])
		if !dotenvKey.MatchString(key) {
			return nil, fmt.Errorf("line %d: invalid variable name %q", lineNo, key)
		}
		val := strings.TrimSpace(line[eq+1:])
		val = unquote(val)
		pairs = append(pairs, [2]string{key, val})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return pairs, nil
}

func unquote(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	// Strip trailing unquoted comments: KEY=value # note
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return v
}
