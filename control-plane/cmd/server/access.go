package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/Bidon15/popsigner/control-plane/internal/config"
	"github.com/Bidon15/popsigner/control-plane/internal/models"
	"github.com/Bidon15/popsigner/control-plane/internal/repository"
	"github.com/Bidon15/popsigner/control-plane/internal/service"
)

// loginPolicy and orgAccess mirror cookieDomain: set once from config before the router is built.
var (
	loginPolicy = service.NewLoginPolicy(nil, nil)
	orgAccess   orgPolicy
)

const notAllowedLoginError = "This account is not allowed to sign in"

// orgPolicy describes the single organization every allowed login joins.
type orgPolicy struct {
	sharedOrg   string
	owners      map[string]struct{}
	defaultRole models.Role
}

func newOrgPolicy(cfg config.AuthConfig) (orgPolicy, error) {
	p := orgPolicy{
		sharedOrg:   strings.TrimSpace(cfg.SharedOrg),
		owners:      make(map[string]struct{}, len(cfg.OwnerEmails)),
		defaultRole: models.Role(strings.ToLower(strings.TrimSpace(cfg.DefaultRole))),
	}
	if p.sharedOrg == "" {
		return p, nil
	}
	if !models.ValidRole(p.defaultRole) || p.defaultRole == models.RoleOwner {
		return p, fmt.Errorf("auth.default_role %q must be admin, operator or viewer", cfg.DefaultRole)
	}
	for _, e := range cfg.OwnerEmails {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			p.owners[e] = struct{}{}
		}
	}
	return p, nil
}

func (p orgPolicy) enabled() bool {
	return p.sharedOrg != ""
}

func (p orgPolicy) roleFor(email string) models.Role {
	if _, ok := p.owners[strings.ToLower(strings.TrimSpace(email))]; ok {
		return models.RoleOwner
	}
	return p.defaultRole
}

// resolveSharedOrg returns the shared organization, creating it on first use, and makes user a
// member. Owners follow config on every call; other roles are left as managed in the UI.
func resolveSharedOrg(ctx context.Context, user *models.User, orgRepo repository.OrgRepository) (*models.Organization, error) {
	org, err := orgRepo.GetBySlug(ctx, orgAccess.sharedOrg)
	if err != nil {
		return nil, err
	}
	if org == nil {
		org = &models.Organization{Name: orgAccess.sharedOrg, Slug: orgAccess.sharedOrg}
		if err := orgRepo.Create(ctx, org, user.ID); err != nil {
			// Lost the race with another first login: use the winner's organization.
			if org, err = orgRepo.GetBySlug(ctx, orgAccess.sharedOrg); err != nil || org == nil {
				return nil, fmt.Errorf("create shared organization: %w", err)
			}
		} else if err := orgRepo.UpdatePlan(ctx, org.ID, models.PlanEnterprise); err != nil {
			return nil, err
		} else {
			org.Plan = models.PlanEnterprise
		}
	}

	want := orgAccess.roleFor(user.Email)
	member, err := orgRepo.GetMember(ctx, org.ID, user.ID)
	if err != nil {
		return nil, err
	}
	switch {
	case member == nil:
		err = orgRepo.AddMember(ctx, org.ID, user.ID, want, nil)
	case (want == models.RoleOwner) != (member.Role == models.RoleOwner):
		err = orgRepo.UpdateMemberRole(ctx, org.ID, user.ID, want)
	}
	if err != nil {
		return nil, err
	}
	return org, nil
}

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
