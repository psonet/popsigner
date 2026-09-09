package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
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

var errNotMember = errors.New("user is not a member of the shared organization")

// Same shape generateSlug produces; organizations.slug is VARCHAR(100).
var slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

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
	if len(p.sharedOrg) > 100 || !slugPattern.MatchString(p.sharedOrg) {
		return p, fmt.Errorf("auth.shared_org %q must be a slug: lowercase letters, digits and single dashes", cfg.SharedOrg)
	}
	if !models.ValidRole(p.defaultRole) || p.defaultRole == models.RoleOwner {
		return p, fmt.Errorf("auth.default_role %q must be admin, operator or viewer", cfg.DefaultRole)
	}
	for _, e := range cfg.OwnerEmails {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			p.owners[e] = struct{}{}
		}
	}
	// Without an owner nobody could ever manage roles or delete keys.
	if len(p.owners) == 0 {
		return p, errors.New("auth.owner_emails must name at least one owner when auth.shared_org is set")
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

// writeOrgError answers an ensureUserHasOrg failure: 403 for a non-member, 500 otherwise.
func writeOrgError(w http.ResponseWriter, err error) {
	if errors.Is(err, errNotMember) {
		http.Error(w, "You are not a member of this organization", http.StatusForbidden)
		return
	}
	http.Error(w, "Failed to get organization", http.StatusInternalServerError)
}

func roleAllows(member *models.OrgMember, required models.Role) bool {
	return member != nil && models.RoleLevel(member.Role) >= models.RoleLevel(required)
}

// requireRole returns false after writing the response unless user holds at least required in org.
func requireRole(w http.ResponseWriter, r *http.Request, orgRepo repository.OrgRepository, org *models.Organization, user *models.User, required models.Role) bool {
	member, err := orgRepo.GetMember(r.Context(), org.ID, user.ID)
	if err != nil {
		http.Error(w, "Failed to check permissions", http.StatusInternalServerError)
		return false
	}
	if !roleAllows(member, required) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// joinSharedOrg runs at login: it creates the shared organization on first use and makes user a
// member. Owners follow config on every login; other roles are left as managed in the UI.
func joinSharedOrg(ctx context.Context, user *models.User, orgRepo repository.OrgRepository) (*models.Organization, error) {
	org, err := orgRepo.GetBySlug(ctx, orgAccess.sharedOrg)
	if err != nil {
		return nil, err
	}
	if org == nil {
		org = &models.Organization{Name: orgAccess.sharedOrg, Slug: orgAccess.sharedOrg}
		if createErr := orgRepo.Create(ctx, org, user.ID); createErr != nil {
			// Lost the race with another first login: use the winner's organization.
			if org, err = orgRepo.GetBySlug(ctx, orgAccess.sharedOrg); err != nil || org == nil {
				return nil, fmt.Errorf("create shared organization: %w (re-read: %v)", createErr, err)
			}
		}
	}
	// Plan limits would otherwise cap keys and members for the whole deployment.
	if org.Plan != models.PlanEnterprise {
		if err := orgRepo.UpdatePlan(ctx, org.ID, models.PlanEnterprise); err != nil {
			return nil, err
		}
		org.Plan = models.PlanEnterprise
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

// sharedOrgFor returns the shared organization for a current member. It never provisions, so a
// member removed on the Team page stays out until their next login.
func sharedOrgFor(ctx context.Context, user *models.User, orgRepo repository.OrgRepository) (*models.Organization, error) {
	org, err := orgRepo.GetBySlug(ctx, orgAccess.sharedOrg)
	if err != nil {
		return nil, err
	}
	if org == nil {
		return nil, errNotMember
	}
	member, err := orgRepo.GetMember(ctx, org.ID, user.ID)
	if err != nil {
		return nil, err
	}
	if member == nil {
		return nil, errNotMember
	}
	return org, nil
}
