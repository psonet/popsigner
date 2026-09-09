package main

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/Bidon15/popsigner/control-plane/internal/models"
	apierrors "github.com/Bidon15/popsigner/control-plane/internal/pkg/errors"
	"github.com/Bidon15/popsigner/control-plane/internal/repository"
	"github.com/Bidon15/popsigner/control-plane/internal/service"
	"github.com/Bidon15/popsigner/control-plane/templates/pages"
)

// writeOrgServiceError maps the org service's typed errors to their status; anything else is a 500
// with a generic body so database errors never reach the browser.
func writeOrgServiceError(w http.ResponseWriter, action string, err error) {
	var apiErr *apierrors.APIError
	if errors.As(err, &apiErr) {
		http.Error(w, apiErr.Message, apiErr.StatusCode)
		return
	}
	slog.Error("Failed to "+action, slog.String("error", err.Error()))
	http.Error(w, "Failed to "+action, http.StatusInternalServerError)
}

func teamMemberDisplay(m *models.OrgMember, currentUserID uuid.UUID) *pages.TeamMemberDisplay {
	d := &pages.TeamMemberDisplay{
		ID:            m.UserID,
		Role:          m.Role,
		JoinedAt:      m.JoinedAt.Format("Jan 2, 2006"),
		IsCurrentUser: m.UserID == currentUserID,
	}
	if m.User != nil {
		d.Email = m.User.Email
		if m.User.Name != nil {
			d.Name = *m.User.Name
		}
		if m.User.AvatarURL != nil {
			d.AvatarURL = *m.User.AvatarURL
		}
	}
	return d
}

// settingsTeamHandler serves the team settings page.
func settingsTeamHandler(sessionRepo repository.SessionRepository, userRepo repository.UserRepository, orgRepo repository.OrgRepository, orgSvc service.OrgService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getAuthenticatedUser(w, r, sessionRepo, userRepo)
		if user == nil {
			return
		}

		org, err := ensureUserHasOrg(r.Context(), user, orgRepo)
		if err != nil || org == nil {
			http.Error(w, "Failed to get organization", http.StatusInternalServerError)
			return
		}

		members, err := orgSvc.ListMembers(r.Context(), org.ID, user.ID)
		if err != nil {
			slog.Error("Failed to list team members", slog.String("org_id", org.ID.String()), slog.String("error", err.Error()))
			http.Error(w, "Failed to list team members", http.StatusInternalServerError)
			return
		}

		currentRole := models.RoleViewer
		displayMembers := make([]*pages.TeamMemberDisplay, 0, len(members))
		for _, m := range members {
			if m.UserID == user.ID {
				currentRole = m.Role
			}
			displayMembers = append(displayMembers, teamMemberDisplay(m, user.ID))
		}

		dashData := buildDashboardData(user, "/settings/team")
		dashData.OrgName = org.Name
		dashData.OrgPlan = string(org.Plan)

		data := pages.TeamPageData{
			DashboardData: dashData,
			Members:       displayMembers,
			Invitations:   nil,
			CurrentRole:   currentRole,
			MemberLimit:   models.GetPlanLimits(org.Plan).TeamMembers,
			MemberCount:   len(members),
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		pages.SettingsTeamPage(data).Render(r.Context(), w)
	}
}

// settingsTeamEditModalHandler returns the change-role modal for one member.
func settingsTeamEditModalHandler(sessionRepo repository.SessionRepository, userRepo repository.UserRepository, orgRepo repository.OrgRepository, orgSvc service.OrgService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getAuthenticatedUser(w, r, sessionRepo, userRepo)
		if user == nil {
			return
		}

		memberID, err := uuid.Parse(chi.URLParam(r, "id"))
		if err != nil {
			http.Error(w, "Invalid member ID", http.StatusBadRequest)
			return
		}

		org, err := ensureUserHasOrg(r.Context(), user, orgRepo)
		if err != nil || org == nil {
			http.Error(w, "Failed to get organization", http.StatusInternalServerError)
			return
		}
		if !requireRole(w, r, orgRepo, org, user, models.RoleAdmin) {
			return
		}

		members, err := orgSvc.ListMembers(r.Context(), org.ID, user.ID)
		if err != nil {
			http.Error(w, "Failed to list team members", http.StatusInternalServerError)
			return
		}
		for _, m := range members {
			if m.UserID == memberID {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				pages.EditMemberRoleModal(teamMemberDisplay(m, user.ID)).Render(r.Context(), w)
				return
			}
		}
		http.Error(w, "Member not found", http.StatusNotFound)
	}
}

// settingsTeamUpdateRoleHandler changes a member's role. The org service enforces
// that the caller is an admin and outranks both the member and the new role.
func settingsTeamUpdateRoleHandler(sessionRepo repository.SessionRepository, userRepo repository.UserRepository, orgRepo repository.OrgRepository, orgSvc service.OrgService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getAuthenticatedUser(w, r, sessionRepo, userRepo)
		if user == nil {
			return
		}

		memberID, err := uuid.Parse(chi.URLParam(r, "id"))
		if err != nil {
			http.Error(w, "Invalid member ID", http.StatusBadRequest)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		role := models.Role(r.FormValue("role"))
		if !models.ValidRole(role) {
			http.Error(w, "Invalid role", http.StatusBadRequest)
			return
		}

		org, err := ensureUserHasOrg(r.Context(), user, orgRepo)
		if err != nil || org == nil {
			http.Error(w, "Failed to get organization", http.StatusInternalServerError)
			return
		}

		if err := orgSvc.UpdateMemberRole(r.Context(), org.ID, memberID, role, user.ID); err != nil {
			writeOrgServiceError(w, "update member role", err)
			return
		}

		slog.Info("Team member role updated",
			slog.String("org_id", org.ID.String()),
			slog.String("actor_id", user.ID.String()),
			slog.String("member_id", memberID.String()),
			slog.String("role", string(role)),
		)
		w.Header().Set("HX-Refresh", "true")
		w.WriteHeader(http.StatusOK)
	}
}

// settingsTeamRemoveHandler removes a member from the organization.
func settingsTeamRemoveHandler(sessionRepo repository.SessionRepository, userRepo repository.UserRepository, orgRepo repository.OrgRepository, orgSvc service.OrgService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getAuthenticatedUser(w, r, sessionRepo, userRepo)
		if user == nil {
			return
		}

		memberID, err := uuid.Parse(chi.URLParam(r, "id"))
		if err != nil {
			http.Error(w, "Invalid member ID", http.StatusBadRequest)
			return
		}

		org, err := ensureUserHasOrg(r.Context(), user, orgRepo)
		if err != nil || org == nil {
			http.Error(w, "Failed to get organization", http.StatusInternalServerError)
			return
		}

		if err := orgSvc.RemoveMember(r.Context(), org.ID, memberID, user.ID); err != nil {
			writeOrgServiceError(w, "remove member", err)
			return
		}

		slog.Info("Team member removed",
			slog.String("org_id", org.ID.String()),
			slog.String("actor_id", user.ID.String()),
			slog.String("member_id", memberID.String()),
		)
		w.Header().Set("HX-Refresh", "true")
		w.WriteHeader(http.StatusOK)
	}
}
