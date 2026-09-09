package service

import (
	"errors"
	"fmt"
	"strings"
)

// ErrEmailNotAllowed is returned when a login's email matches neither the allowed domains nor the allowed emails.
var ErrEmailNotAllowed = errors.New("email is not allowed to sign in")

// LoginPolicy decides which emails may sign in. An empty policy allows everyone.
type LoginPolicy struct {
	domains map[string]struct{}
	emails  map[string]struct{}
}

// NewLoginPolicy builds a policy from allowed email domains and exact emails.
// Entries are matched case-insensitively; a leading "@" on a domain is ignored.
func NewLoginPolicy(domains, emails []string) *LoginPolicy {
	p := &LoginPolicy{
		domains: make(map[string]struct{}, len(domains)),
		emails:  make(map[string]struct{}, len(emails)),
	}
	for _, d := range domains {
		d = strings.TrimPrefix(normalizeEmail(d), "@")
		if d != "" {
			p.domains[d] = struct{}{}
		}
	}
	for _, e := range emails {
		if e = normalizeEmail(e); e != "" {
			p.emails[e] = struct{}{}
		}
	}
	return p
}

// ValidateLoginAllowlist rejects entries that could never match, so a typo fails startup
// instead of silently locking someone out or leaving login open.
func ValidateLoginAllowlist(domains, emails []string) error {
	for _, d := range domains {
		if d = strings.TrimPrefix(normalizeEmail(d), "@"); strings.ContainsAny(d, "@ ") || (d == "" && len(domains) > 0) {
			return fmt.Errorf("allowed_email_domains entry %q is not a domain", d)
		}
	}
	for _, e := range emails {
		if e = normalizeEmail(e); !strings.Contains(e, "@") || strings.ContainsAny(e, " ") {
			return fmt.Errorf("allowed_emails entry %q is not an email address", e)
		}
	}
	return nil
}

// Enabled reports whether the policy restricts logins at all. A nil policy restricts nothing.
func (p *LoginPolicy) Enabled() bool {
	return p != nil && len(p.domains)+len(p.emails) > 0
}

// Allows reports whether email may sign in under this policy.
func (p *LoginPolicy) Allows(email string) bool {
	if !p.Enabled() {
		return true
	}
	email = normalizeEmail(email)
	if _, ok := p.emails[email]; ok {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	_, ok := p.domains[email[at+1:]]
	return ok
}

func normalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
