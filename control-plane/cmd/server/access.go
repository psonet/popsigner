package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/url"
	"strings"

	"github.com/Bidon15/popsigner/control-plane/internal/service"
)

// loginPolicy mirrors cookieDomain: set once from config before the router is built.
var loginPolicy = service.NewLoginPolicy(nil, nil)

const notAllowedLoginError = "This account is not allowed to sign in"

func newOAuthState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func stateMatches(cookieValue, param string) bool {
	return cookieValue != "" && subtle.ConstantTimeCompare([]byte(cookieValue), []byte(param)) == 1
}

// popkinsReturnTo is where a login started on the POPKins host lands afterwards. The callback
// arrives on the main host, so this has to be absolute; safeReturnTo re-checks it there.
func popkinsReturnTo(host string) string {
	return safeReturnTo("https://" + host + "/deployments")
}

// safeReturnTo accepts same-site paths, plus https URLs on a subdomain of the cookie domain
// (the POPKins host). Everything else falls back to the dashboard.
func safeReturnTo(v string) string {
	if strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") && !strings.ContainsAny(v, "\\\r\n") {
		return v
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.User != nil || cookieDomain == "" {
		return "/dashboard"
	}
	if strings.HasSuffix(strings.ToLower(u.Hostname()), "."+strings.TrimPrefix(cookieDomain, ".")) {
		return v
	}
	return "/dashboard"
}
