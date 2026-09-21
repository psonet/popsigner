package service

import (
	"errors"
	"strings"
	"testing"
)

func TestLoginPolicy_Allows(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		emails  []string
		email   string
		want    bool
	}{
		{"disabled policy allows anyone", nil, nil, "anyone@evil.example", true},
		{"domain match", []string{"a.example"}, nil, "user@a.example", true},
		{"domain match is case-insensitive", []string{"A.Example"}, nil, "User@a.EXAMPLE", true},
		{"domain with leading @", []string{"@a.example"}, nil, "user@a.example", true},
		{"subdomain is not the domain", []string{"a.example"}, nil, "user@sub.a.example", false},
		{"other domain refused", []string{"a.example"}, nil, "user@evil.example", false},
		{"exact email match", nil, []string{"guest@c.example"}, "guest@c.example", true},
		{"exact email is case-insensitive", nil, []string{"Guest@C.example"}, " guest@c.example ", true},
		{"exact email does not admit its domain", nil, []string{"guest@c.example"}, "other@c.example", false},
		{"no @ in email", []string{"a.example"}, nil, "a.example", false},
		{"blank entries are ignored", []string{" ", ""}, []string{""}, "anyone@evil.example", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewLoginPolicy(tt.domains, tt.emails).Allows(tt.email); got != tt.want {
				t.Fatalf("Allows(%q) = %v, want %v", tt.email, got, tt.want)
			}
		})
	}
}

func TestLoginPolicy_Enabled(t *testing.T) {
	var nilPolicy *LoginPolicy
	if nilPolicy.Enabled() || !nilPolicy.Allows("anyone@evil.example") {
		t.Fatal("nil policy must allow everyone")
	}
	if NewLoginPolicy(nil, nil).Enabled() {
		t.Fatal("empty policy must not be enabled")
	}
	if !NewLoginPolicy([]string{"a.example"}, nil).Enabled() {
		t.Fatal("domain policy must be enabled")
	}
	if !NewLoginPolicy(nil, []string{"x@a.example"}).Enabled() {
		t.Fatal("email policy must be enabled")
	}
}

func TestOAuthService_Admit(t *testing.T) {
	svc := &oauthService{policy: NewLoginPolicy([]string{"a.example"}, nil)}
	if err := svc.admit(&OAuthUserInfo{Email: "user@a.example"}); err != nil {
		t.Fatalf("allowed email refused: %v", err)
	}
	err := svc.admit(&OAuthUserInfo{Email: "user@evil.example"})
	if !errors.Is(err, ErrEmailNotAllowed) {
		t.Fatalf("expected ErrEmailNotAllowed, got %v", err)
	}
}

func TestParseGoogleUser(t *testing.T) {
	info, err := parseGoogleUser(strings.NewReader(`{"id":"g1","email":"u@a.example","verified_email":true,"name":"U","picture":"p"}`))
	if err != nil {
		t.Fatal(err)
	}
	if info.ID != "g1" || info.Email != "u@a.example" || info.Name != "U" || info.AvatarURL != "p" {
		t.Fatalf("unexpected user info: %+v", info)
	}
}

func TestParseGoogleUser_Unverified(t *testing.T) {
	_, err := parseGoogleUser(strings.NewReader(`{"id":"g1","email":"u@a.example","verified_email":false}`))
	if err == nil {
		t.Fatal("unverified Google email must be rejected")
	}
}

func TestValidateLoginAllowlist(t *testing.T) {
	valid := [][2][]string{
		{nil, nil},
		{{"a.example", "@b.example"}, nil},
		{nil, {"guest@c.example", " Root@A.example "}},
	}
	for _, v := range valid {
		if err := ValidateLoginAllowlist(v[0], v[1]); err != nil {
			t.Errorf("ValidateLoginAllowlist(%v, %v) = %v, want nil", v[0], v[1], err)
		}
	}
	invalid := [][2][]string{
		{{"user@a.example"}, nil},
		{{""}, nil},
		{{"a example"}, nil},
		{nil, {"user.a.example"}},
		{nil, {""}},
		{nil, {"user @a.example"}},
	}
	for _, v := range invalid {
		if err := ValidateLoginAllowlist(v[0], v[1]); err == nil {
			t.Errorf("ValidateLoginAllowlist(%v, %v) = nil, want error", v[0], v[1])
		}
	}
}
