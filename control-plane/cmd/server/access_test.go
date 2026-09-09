package main

import (
	"strings"
	"testing"
)

func TestNewOAuthState_UniqueAndURLSafe(t *testing.T) {
	a, err := newOAuthState()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newOAuthState()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two states must differ")
	}
	if len(a) < 40 || strings.ContainsAny(a, "+/=") {
		t.Fatalf("state %q is not URL-safe base64 of 32 bytes", a)
	}
}

func TestStateMatches(t *testing.T) {
	if !stateMatches("abc", "abc") {
		t.Fatal("equal values must match")
	}
	if stateMatches("abc", "abd") {
		t.Fatal("different values must not match")
	}
	if stateMatches("", "") {
		t.Fatal("an empty cookie must never match")
	}
}

func TestSafeReturnTo(t *testing.T) {
	tests := map[string]string{
		"/keys":                 "/keys",
		"/settings/team?x=1":    "/settings/team?x=1",
		"":                      "/dashboard",
		"//evil.example/x":      "/dashboard",
		"https://evil.example":  "/dashboard",
		"/\\evil.example":       "/dashboard",
		"/keys\r\nSet-Cookie:x": "/dashboard",
		"keys":                  "/dashboard",
	}
	for in, want := range tests {
		if got := safeReturnTo(in); got != want {
			t.Errorf("safeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSafeReturnTo_AbsoluteUnderCookieDomain(t *testing.T) {
	defer func(old string) { cookieDomain = old }(cookieDomain)

	cookieDomain = ""
	if got := safeReturnTo("https://popkins.a.example/deployments"); got != "/dashboard" {
		t.Fatalf("host-only cookies must reject absolute URLs, got %q", got)
	}

	cookieDomain = ".a.example"
	tests := map[string]string{
		"https://popkins.a.example/deployments":   "https://popkins.a.example/deployments",
		"https://POPKINS.a.example:8443/x":        "https://POPKINS.a.example:8443/x",
		"http://popkins.a.example/deployments":    "/dashboard",
		"https://a.example/deployments":           "/dashboard",
		"https://evila.example/deployments":       "/dashboard",
		"https://popkins.a.example.evil.example/": "/dashboard",
		"https://user@popkins.a.example/":         "/dashboard",
	}
	for in, want := range tests {
		if got := safeReturnTo(in); got != want {
			t.Errorf("safeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
	if got := popkinsReturnTo("popkins.a.example"); got != "https://popkins.a.example/deployments" {
		t.Fatalf("popkinsReturnTo = %q", got)
	}
}
