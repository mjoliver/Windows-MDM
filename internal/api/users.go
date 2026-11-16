package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/latchzmdm/latchz/internal/auth"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

// UserSummary is the safe JSON representation of a user account (never exposes password_hash).
type UserSummary struct {
	ID           string     `json:"id"`
	Email        string     `json:"email"`
	DisplayName  string     `json:"display_name"`
	Role         string     `json:"role"`
	AuthProvider string     `json:"auth_provider"`
	HasPassword  bool       `json:"has_password"`
	TOTPEnabled  bool       `json:"totp_enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	LastLogin    *time.Time `json:"last_login"`
}

func validRole(role string) bool {
	switch role {
	case "super_admin", "admin", "user":
		return true
	default:
		return false
	}
}

// HandleListUsers returns all registered user accounts.
// GET /api/users (requires admin or super_admin)
func (h *Handler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT id, email, COALESCE(display_name,''), role, auth_provider,
		       CASE WHEN COALESCE(password_hash,'') <> '' THEN 1 ELSE 0 END,
		       COALESCE(totp_enabled, 0),
		       created_at, last_login
		FROM users
		ORDER BY created_at ASC
	`))
	if err != nil {
		slog.Error("api: listing users", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	defer rows.Close()

	users := []UserSummary{}
	for rows.Next() {
		var u UserSummary
		var hasPW, totpEn int
		if err := rows.Scan(
			&u.ID, &u.Email, &u.DisplayName, &u.Role, &u.AuthProvider,
			&hasPW, &totpEn, &u.CreatedAt, &u.LastLogin,
		); err != nil {
			slog.Error("api: scanning user row", "err", err)
			continue
		}
		u.HasPassword = hasPW == 1
		u.TOTPEnabled = totpEn != 0
		users = append(users, u)
	}
	respondOK(w, users)
}

// HandleCreateUser creates a new user account (builtin or OIDC pre-provisioned).
// POST /api/users (requires super_admin)
func (h *Handler) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	actor := emailFromCtx(r)

	var body struct {
		Email        string `json:"email"`
		DisplayName  string `json:"display_name"`
		Role         string `json:"role"`
		AuthProvider string `json:"auth_provider"`
		Password     string `json:"password"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	email := strings.ToLower(strings.TrimSpace(body.Email))
	if email == "" || !strings.Contains(email, "@") {
		respondErr(w, http.StatusBadRequest, "a valid email address is required")
		return
	}

	role := strings.TrimSpace(body.Role)
	if role == "" {
		role = "user"
	}
	if !validRole(role) {
		respondErr(w, http.StatusBadRequest, "role must be super_admin, admin, or user")
		return
	}

	provider := strings.TrimSpace(body.AuthProvider)
	if provider == "" {
		if body.Password != "" {
			provider = "builtin"
		} else {
			provider = "oidc"
		}
	}
	if provider != "builtin" && provider != "oidc" {
		respondErr(w, http.StatusBadRequest, "auth_provider must be builtin or oidc")
		return
	}

	var pwHash *string
	if body.Password != "" {
		if len(body.Password) < 8 {
			respondErr(w, http.StatusBadRequest, "password must be at least 8 characters")
			return
		}
		hashed, err := auth.HashPassword(body.Password)
		if err != nil {
			respondErr(w, http.StatusInternalServerError, "failed to hash password")
			return
		}
		pwHash = &hashed
	}

	var existing int
	_ = h.db.QueryRowContext(r.Context(),
		dbpkg.Rebind(`SELECT COUNT(*) FROM users WHERE LOWER(email) = ?`), email,
	).Scan(&existing)
	if existing > 0 {
		respondErr(w, http.StatusConflict, "a user with this email already exists")
		return
	}

	id := uuid.New().String()
	displayName := strings.TrimSpace(body.DisplayName)
	if _, err := h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO users (id, email, display_name, role, auth_provider, password_hash)
		VALUES (?, ?, ?, ?, ?, ?)
	`), id, email, displayName, role, provider, pwHash); err != nil {
		slog.Error("api: creating user", "email", email, "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	details, _ := json.Marshal(map[string]interface{}{
		"email":         email,
		"role":          role,
		"auth_provider": provider,
		"has_password":  pwHash != nil,
	})
	h.audit(r, actor, "user.create", "user", id, string(details))
	slog.Info("user created", "user_id", id, "email", email, "role", role, "actor", actor)

	u, err := h.getUserByID(r, id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to load created user")
		return
	}
	respondCreated(w, u)
}

// HandleUpdateUser updates a user's role, display name, auth provider, or builtin password.
// PUT /api/users/{id} (requires super_admin)
func (h *Handler) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	target, err := h.getUserByID(r, id)
	if errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	var body struct {
		DisplayName  *string `json:"display_name"`
		Role         *string `json:"role"`
		AuthProvider *string `json:"auth_provider"`
		Password     *string `json:"password"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	newDisplayName := target.DisplayName
	if body.DisplayName != nil {
		newDisplayName = strings.TrimSpace(*body.DisplayName)
	}

	newRole := target.Role
	if body.Role != nil {
		rTrim := strings.TrimSpace(*body.Role)
		if !validRole(rTrim) {
			respondErr(w, http.StatusBadRequest, "role must be super_admin, admin, or user")
			return
		}
		newRole = rTrim
	}

	// Prevent self-demotion from super_admin and prevent removing the last super_admin.
	if target.Role == "super_admin" && newRole != "super_admin" {
		if strings.EqualFold(target.Email, actor) {
			respondErr(w, http.StatusBadRequest, "cannot demote your own super_admin account")
			return
		}
		if h.countSuperAdmins(r) <= 1 {
			respondErr(w, http.StatusBadRequest, "cannot demote the last super_admin")
			return
		}
	}

	newProvider := target.AuthProvider
	if body.AuthProvider != nil && strings.TrimSpace(*body.AuthProvider) != "" {
		p := strings.TrimSpace(*body.AuthProvider)
		if p != "builtin" && p != "oidc" {
			respondErr(w, http.StatusBadRequest, "auth_provider must be builtin or oidc")
			return
		}
		newProvider = p
	}

	pwUpdated := false
	if body.Password != nil && *body.Password != "" {
		if len(*body.Password) < 8 {
			respondErr(w, http.StatusBadRequest, "password must be at least 8 characters")
			return
		}
		hashed, err := auth.HashPassword(*body.Password)
		if err != nil {
			respondErr(w, http.StatusInternalServerError, "failed to hash password")
			return
		}
		newProvider = "builtin"
		if _, err := h.db.ExecContext(r.Context(), dbpkg.Rebind(`
			UPDATE users SET display_name = ?, role = ?, auth_provider = ?, password_hash = ? WHERE id = ?
		`), newDisplayName, newRole, newProvider, hashed, id); err != nil {
			respondErr(w, http.StatusInternalServerError, "failed to update user")
			return
		}
		pwUpdated = true
	} else {
		if _, err := h.db.ExecContext(r.Context(), dbpkg.Rebind(`
			UPDATE users SET display_name = ?, role = ?, auth_provider = ? WHERE id = ?
		`), newDisplayName, newRole, newProvider, id); err != nil {
			respondErr(w, http.StatusInternalServerError, "failed to update user")
			return
		}
	}

	details, _ := json.Marshal(map[string]interface{}{
		"email":            target.Email,
		"role":             newRole,
		"auth_provider":    newProvider,
		"password_updated": pwUpdated,
	})
	h.audit(r, actor, "user.update", "user", id, string(details))
	slog.Info("user updated", "user_id", id, "email", target.Email, "role", newRole, "actor", actor)

	updated, err := h.getUserByID(r, id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to reload user")
		return
	}
	respondOK(w, updated)
}

// HandleDeleteUser deletes a user account, guarding against self-deletion and last-super_admin lockout.
// DELETE /api/users/{id} (requires super_admin)
func (h *Handler) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	target, err := h.getUserByID(r, id)
	if errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	if strings.EqualFold(target.Email, actor) {
		respondErr(w, http.StatusBadRequest, "cannot delete your own account")
		return
	}
	if target.Role == "super_admin" && h.countSuperAdmins(r) <= 1 {
		respondErr(w, http.StatusBadRequest, "cannot delete the last super_admin")
		return
	}

	if _, err := h.db.ExecContext(r.Context(), dbpkg.Rebind(`DELETE FROM users WHERE id = ?`), id); err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to delete user")
		return
	}

	details, _ := json.Marshal(map[string]string{
		"email": target.Email,
		"role":  target.Role,
	})
	h.audit(r, actor, "user.delete", "user", id, string(details))
	slog.Info("user deleted", "user_id", id, "email", target.Email, "actor", actor)

	respondOK(w, map[string]string{"status": "deleted", "id": id})
}

func (h *Handler) getUserByID(r *http.Request, id string) (*UserSummary, error) {
	var u UserSummary
	var hasPW, totpEn int
	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT id, email, COALESCE(display_name,''), role, auth_provider,
		       CASE WHEN COALESCE(password_hash,'') <> '' THEN 1 ELSE 0 END,
		       COALESCE(totp_enabled, 0),
		       created_at, last_login
		FROM users WHERE id = ?
	`), id).Scan(
		&u.ID, &u.Email, &u.DisplayName, &u.Role, &u.AuthProvider,
		&hasPW, &totpEn, &u.CreatedAt, &u.LastLogin,
	)
	if err != nil {
		return nil, err
	}
	u.HasPassword = hasPW == 1
	u.TOTPEnabled = totpEn != 0
	return &u, nil
}

func (h *Handler) countSuperAdmins(r *http.Request) int {
	var n int
	_ = h.db.QueryRowContext(r.Context(),
		dbpkg.Rebind(`SELECT COUNT(*) FROM users WHERE role = 'super_admin'`),
	).Scan(&n)
	return n
}
