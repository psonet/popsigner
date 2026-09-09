package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Bidon15/popsigner/control-plane/internal/config"
	"github.com/Bidon15/popsigner/control-plane/internal/models"
	apierrors "github.com/Bidon15/popsigner/control-plane/internal/pkg/errors"
	"github.com/Bidon15/popsigner/control-plane/internal/repository"
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

func TestNewOrgPolicy(t *testing.T) {
	p, err := newOrgPolicy(config.AuthConfig{})
	if err != nil || p.enabled() {
		t.Fatalf("empty shared_org must disable the policy: %v %+v", err, p)
	}

	p, err = newOrgPolicy(config.AuthConfig{SharedOrg: " platform-eu ", OwnerEmails: []string{" Root@A.example "}, DefaultRole: "Viewer"})
	if err != nil || !p.enabled() {
		t.Fatalf("valid policy rejected: %v", err)
	}
	if p.roleFor("root@a.example") != models.RoleOwner || p.roleFor("user@a.example") != models.RoleViewer {
		t.Fatalf("roles: owner=%q other=%q", p.roleFor("root@a.example"), p.roleFor("user@a.example"))
	}

	for _, role := range []string{"", "owner", "root"} {
		if _, err := newOrgPolicy(config.AuthConfig{SharedOrg: "platform", OwnerEmails: []string{"root@a.example"}, DefaultRole: role}); err == nil {
			t.Fatalf("default_role %q must be rejected", role)
		}
	}
	if _, err := newOrgPolicy(config.AuthConfig{SharedOrg: "platform", OwnerEmails: []string{" "}, DefaultRole: "operator"}); err == nil {
		t.Fatal("shared_org without an owner must be rejected")
	}
	for _, slug := range []string{"Platform", "platform team", "platform_(eu)", "-platform", "platform--eu", strings.Repeat("a", 101)} {
		if _, err := newOrgPolicy(config.AuthConfig{SharedOrg: slug, OwnerEmails: []string{"root@a.example"}, DefaultRole: "operator"}); err == nil {
			t.Fatalf("shared_org %q must be rejected", slug)
		}
	}
}

func TestSharedOrgFor(t *testing.T) {
	defer func(old orgPolicy) { orgAccess = old }(orgAccess)
	orgAccess = orgPolicy{sharedOrg: "platform", owners: map[string]struct{}{}, defaultRole: models.RoleOperator}
	ctx := context.Background()
	existing := &models.Organization{ID: uuid.New(), Slug: "platform"}
	user := &models.User{ID: uuid.New(), Email: "user@a.example"}

	repo := &fakeOrgRepo{org: existing, member: &models.OrgMember{UserID: user.ID, Role: models.RoleViewer}}
	org, err := joinLess(sharedOrgFor(ctx, user, repo))
	if err != nil || org != existing || repo.added != nil || repo.updated != nil {
		t.Fatalf("member lookup: org=%v err=%v added=%v updated=%v", org, err, repo.added, repo.updated)
	}

	repo = &fakeOrgRepo{org: existing}
	if _, err := sharedOrgFor(ctx, user, repo); !errors.Is(err, errNotMember) || repo.added != nil {
		t.Fatalf("removed member must not be re-added: err=%v added=%v", err, repo.added)
	}

	if _, err := sharedOrgFor(ctx, user, &fakeOrgRepo{}); !errors.Is(err, errNotMember) {
		t.Fatalf("missing org must not be created on read: %v", err)
	}
}

func joinLess(org *models.Organization, err error) (*models.Organization, error) { return org, err }

// fakeOrgRepo stubs only what joinSharedOrg touches; any other call panics on the nil embed.
type fakeOrgRepo struct {
	repository.OrgRepository
	org       *models.Organization
	member    *models.OrgMember
	createErr error
	memberErr error
	plan      models.Plan
	added     *models.Role
	updated   *models.Role
}

func (f *fakeOrgRepo) GetBySlug(_ context.Context, slug string) (*models.Organization, error) {
	if f.org != nil && f.org.Slug == slug {
		return f.org, nil
	}
	return nil, nil
}

func (f *fakeOrgRepo) Create(_ context.Context, org *models.Organization, ownerID uuid.UUID) error {
	if f.createErr != nil {
		return f.createErr
	}
	org.ID = uuid.New()
	org.Plan = models.PlanFree
	f.org = org
	f.member = &models.OrgMember{OrgID: org.ID, UserID: ownerID, Role: models.RoleOwner}
	return nil
}

func (f *fakeOrgRepo) UpdatePlan(_ context.Context, _ uuid.UUID, plan models.Plan) error {
	f.plan = plan
	return nil
}

func (f *fakeOrgRepo) GetMember(_ context.Context, _ uuid.UUID, userID uuid.UUID) (*models.OrgMember, error) {
	if f.memberErr != nil {
		return nil, f.memberErr
	}
	if f.member != nil && f.member.UserID == userID {
		return f.member, nil
	}
	return nil, nil
}

func (f *fakeOrgRepo) AddMember(_ context.Context, _ uuid.UUID, _ uuid.UUID, role models.Role, _ *uuid.UUID) error {
	f.added = &role
	return nil
}

func (f *fakeOrgRepo) UpdateMemberRole(_ context.Context, _ uuid.UUID, _ uuid.UUID, role models.Role) error {
	f.updated = &role
	return nil
}

func TestResolveSharedOrg(t *testing.T) {
	defer func(old orgPolicy) { orgAccess = old }(orgAccess)
	orgAccess = orgPolicy{sharedOrg: "platform", owners: map[string]struct{}{"root@a.example": {}}, defaultRole: models.RoleOperator}
	ctx := context.Background()
	existing := &models.Organization{ID: uuid.New(), Slug: "platform", Plan: models.PlanEnterprise}

	t.Run("first login creates the org and takes the configured role", func(t *testing.T) {
		repo := &fakeOrgRepo{}
		user := &models.User{ID: uuid.New(), Email: "user@a.example"}
		org, err := joinSharedOrg(ctx, user, repo)
		if err != nil {
			t.Fatal(err)
		}
		if org.Slug != "platform" || org.Plan != models.PlanEnterprise || repo.plan != models.PlanEnterprise {
			t.Fatalf("org = %+v, plan set = %q", org, repo.plan)
		}
		if repo.updated == nil || *repo.updated != models.RoleOperator {
			t.Fatalf("creator must be demoted from owner to the default role, got %v", repo.updated)
		}
	})

	t.Run("lost creation race falls back to the winner", func(t *testing.T) {
		repo := &fakeOrgRepo{createErr: errors.New("duplicate slug")}
		user := &models.User{ID: uuid.New(), Email: "user@a.example"}
		if _, err := joinSharedOrg(ctx, user, repo); err == nil {
			t.Fatal("no winner to fall back to must error")
		}
	})

	t.Run("new member joins with default role", func(t *testing.T) {
		repo := &fakeOrgRepo{org: existing}
		user := &models.User{ID: uuid.New(), Email: "user@a.example"}
		if _, err := joinSharedOrg(ctx, user, repo); err != nil {
			t.Fatal(err)
		}
		if repo.added == nil || *repo.added != models.RoleOperator || repo.updated != nil {
			t.Fatalf("added=%v updated=%v", repo.added, repo.updated)
		}
	})

	t.Run("configured owner is promoted", func(t *testing.T) {
		user := &models.User{ID: uuid.New(), Email: "Root@a.example"}
		repo := &fakeOrgRepo{org: existing, member: &models.OrgMember{UserID: user.ID, Role: models.RoleViewer}}
		if _, err := joinSharedOrg(ctx, user, repo); err != nil {
			t.Fatal(err)
		}
		if repo.updated == nil || *repo.updated != models.RoleOwner {
			t.Fatalf("owner not promoted: %v", repo.updated)
		}
	})

	t.Run("owner dropped from config is demoted", func(t *testing.T) {
		user := &models.User{ID: uuid.New(), Email: "former@a.example"}
		repo := &fakeOrgRepo{org: existing, member: &models.OrgMember{UserID: user.ID, Role: models.RoleOwner}}
		if _, err := joinSharedOrg(ctx, user, repo); err != nil {
			t.Fatal(err)
		}
		if repo.updated == nil || *repo.updated != models.RoleOperator {
			t.Fatalf("ex-owner not demoted: %v", repo.updated)
		}
	})

	t.Run("UI-managed role is left alone", func(t *testing.T) {
		user := &models.User{ID: uuid.New(), Email: "user@a.example"}
		repo := &fakeOrgRepo{org: existing, member: &models.OrgMember{UserID: user.ID, Role: models.RoleAdmin}}
		if _, err := joinSharedOrg(ctx, user, repo); err != nil {
			t.Fatal(err)
		}
		if repo.added != nil || repo.updated != nil {
			t.Fatalf("membership must not change: added=%v updated=%v", repo.added, repo.updated)
		}
	})
}

func TestRoleAllows(t *testing.T) {
	tests := []struct {
		name     string
		member   *models.OrgMember
		required models.Role
		want     bool
	}{
		{"no membership", nil, models.RoleViewer, false},
		{"viewer below operator", &models.OrgMember{Role: models.RoleViewer}, models.RoleOperator, false},
		{"viewer is a viewer", &models.OrgMember{Role: models.RoleViewer}, models.RoleViewer, true},
		{"operator below admin", &models.OrgMember{Role: models.RoleOperator}, models.RoleAdmin, false},
		{"admin at least operator", &models.OrgMember{Role: models.RoleAdmin}, models.RoleOperator, true},
		{"owner at least admin", &models.OrgMember{Role: models.RoleOwner}, models.RoleAdmin, true},
		{"unknown role never passes", &models.OrgMember{Role: "root"}, models.RoleViewer, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := roleAllows(tt.member, tt.required); got != tt.want {
				t.Fatalf("roleAllows = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRequireRole(t *testing.T) {
	org := &models.Organization{ID: uuid.New()}
	user := &models.User{ID: uuid.New()}
	tests := []struct {
		name       string
		repo       *fakeOrgRepo
		required   models.Role
		want       bool
		wantStatus int
	}{
		{"sufficient rank passes without writing", &fakeOrgRepo{member: &models.OrgMember{UserID: user.ID, Role: models.RoleAdmin}}, models.RoleOperator, true, http.StatusOK},
		{"insufficient rank is forbidden", &fakeOrgRepo{member: &models.OrgMember{UserID: user.ID, Role: models.RoleViewer}}, models.RoleOperator, false, http.StatusForbidden},
		{"non-member is forbidden", &fakeOrgRepo{}, models.RoleViewer, false, http.StatusForbidden},
		{"repository failure is a server error", &fakeOrgRepo{memberErr: errors.New("db down")}, models.RoleViewer, false, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/keys", nil)
			if got := requireRole(w, r, tt.repo, org, user, tt.required); got != tt.want {
				t.Fatalf("requireRole = %v, want %v", got, tt.want)
			}
			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if tt.want && w.Body.Len() != 0 {
				t.Fatalf("passing gate must not write a body, got %q", w.Body.String())
			}
		})
	}
}

func TestWriteOrgError(t *testing.T) {
	w := httptest.NewRecorder()
	writeOrgError(w, errNotMember)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-member status = %d", w.Code)
	}
	w = httptest.NewRecorder()
	writeOrgError(w, errors.New("connection refused"))
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "connection refused") {
		t.Fatalf("other errors must be a generic 500, got %d %q", w.Code, w.Body.String())
	}
}

func TestWriteOrgServiceError(t *testing.T) {
	w := httptest.NewRecorder()
	writeOrgServiceError(w, "remove member", apierrors.ErrForbidden.WithMessage("Cannot remove the organization owner"))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Cannot remove the organization owner") {
		t.Fatalf("typed error must keep its status and message, got %d %q", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	writeOrgServiceError(w, "remove member", apierrors.NewNotFoundError("Member"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("not found status = %d", w.Code)
	}
	w = httptest.NewRecorder()
	writeOrgServiceError(w, "remove member", errors.New("ERROR: relation missing (SQLSTATE 42P01)"))
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "SQLSTATE") {
		t.Fatalf("opaque errors must be a generic 500, got %d %q", w.Code, w.Body.String())
	}
}

func TestTeamMemberDisplay(t *testing.T) {
	me := uuid.New()
	name, avatar := "Ada", "https://img.example/a.png"
	joined := time.Date(2026, time.March, 4, 0, 0, 0, 0, time.UTC)

	full := teamMemberDisplay(&models.OrgMember{UserID: me, Role: models.RoleAdmin, JoinedAt: joined,
		User: &models.User{Email: "ada@a.example", Name: &name, AvatarURL: &avatar}}, me)
	if full.Name != "Ada" || full.Email != "ada@a.example" || full.AvatarURL != avatar || !full.IsCurrentUser || full.JoinedAt != "Mar 4, 2026" || full.Role != models.RoleAdmin {
		t.Fatalf("unexpected display: %+v", full)
	}

	bare := teamMemberDisplay(&models.OrgMember{UserID: uuid.New(), Role: models.RoleViewer, JoinedAt: joined, User: &models.User{Email: "x@a.example"}}, me)
	if bare.Name != "" || bare.AvatarURL != "" || bare.IsCurrentUser || bare.Email != "x@a.example" {
		t.Fatalf("nil name/avatar must render empty: %+v", bare)
	}

	noUser := teamMemberDisplay(&models.OrgMember{UserID: uuid.New(), Role: models.RoleViewer, JoinedAt: joined}, me)
	if noUser.Email != "" || noUser.Name != "" {
		t.Fatalf("missing user must not panic and renders empty: %+v", noUser)
	}
}
