package manifest

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// BuildHeader converts an authHeader spec and a token into a wire header.
//
//	bearer            -> Authorization: Bearer <t>
//	basic:<user>      -> Authorization: Basic b64(user:t)
//	token=            -> Authorization: Token token=<t>   (PagerDuty style)
//	private-token     -> PRIVATE-TOKEN: <t>               (GitLab style)
//	header:<Name>     -> <Name>: <t>
//
// An empty spec defaults to bearer.
func BuildHeader(spec, token string) (name, value string, err error) {
	switch {
	case spec == "" || spec == "bearer":
		return "Authorization", "Bearer " + token, nil
	case strings.HasPrefix(spec, "basic:"):
		user := strings.TrimPrefix(spec, "basic:")
		if user == "" {
			return "", "", fmt.Errorf("authHeader %q: missing username after basic:", spec)
		}
		b64 := base64.StdEncoding.EncodeToString([]byte(user + ":" + token))
		return "Authorization", "Basic " + b64, nil
	case spec == "token=":
		return "Authorization", "Token token=" + token, nil
	case spec == "private-token":
		return "PRIVATE-TOKEN", token, nil
	case strings.HasPrefix(spec, "header:"):
		h := strings.TrimPrefix(spec, "header:")
		if h == "" {
			return "", "", fmt.Errorf("authHeader %q: missing header name after header:", spec)
		}
		return h, token, nil
	default:
		return "", "", fmt.Errorf("unknown authHeader %q", spec)
	}
}
