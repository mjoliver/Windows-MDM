package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/latchzmdm/latchz/internal/auth"
	"github.com/latchzmdm/latchz/internal/testutil"
)

func authedReq(method, target, body, email, role string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	ctx := context.WithValue(r.Context(), CtxKeyEmail, email)
	ctx = context.WithValue(ctx, CtxKeyRole, role)
	return r.WithContext(ctx)
}

func TestUsersLifecycleAndLockoutGuards(t *testing.T) {
	database := testutil.DB(t)
	h := NewHandler(database.DB)

	r := chi.NewRouter()
	r.Get("/users", h.HandleListUsers)
	r.Post("/users", h.HandleCreateUser)
	r.Put("/users/{id}", h.HandleUpdateUser)
	r.Delete("/users/{id}", h.HandleDeleteUser)
	r.Get("/audit", h.HandleListAudit)

	// 1. Create initial super_admin
	w := httptest.NewRecorder()
	r.ServeHTTP(w, authedReq("POST", "/users", `{"email":"Owner@Example.com","display_name":"Owner","role":"super_admin","password":"correct-horse-battery"}`, "owner@example.com", "super_admin"))
	if w.Code != http.StatusCreated {
		t.Fatalf("create super_admin: status %d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "argon2id") || strings.Contains(w.Body.String(), "password_hash") {
		t.Fatalf("response leaked password hash: %s", w.Body.String())
	}
	var owner UserSummary
	if err := json.Unmarshal(w.Body.Bytes(), &owner); err != nil {
		t.Fatal(err)
	}
	if owner.Email != "owner@example.com" || !owner.HasPassword {
		t.Fatalf("unexpected created owner: %+v", owner)
	}

	// Verify stored password hash works with auth.VerifyPassword
	var storedHash string
	if err := database.QueryRow(`SELECT password_hash FROM users WHERE id = ?`, owner.ID).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if !auth.VerifyPassword("correct-horse-battery", storedHash) {
		t.Fatal("stored password hash failed verification")
	}

	// 2. Duplicate email -> 409 Conflict
	wDup := httptest.NewRecorder()
	r.ServeHTTP(wDup, authedReq("POST", "/users", `{"email":"owner@example.com","role":"user"}`, "owner@example.com", "super_admin"))
	if wDup.Code != http.StatusConflict {
		t.Fatalf("duplicate email: want 409, got %d", wDup.Code)
	}

	// 3. Short password -> 400 Bad Request
	wShort := httptest.NewRecorder()
	r.ServeHTTP(wShort, authedReq("POST", "/users", `{"email":"short@example.com","role":"user","password":"123"}`, "owner@example.com", "super_admin"))
	if wShort.Code != http.StatusBadRequest {
		t.Fatalf("short password: want 400, got %d", wShort.Code)
	}

	// 4. Self-demotion & last-super_admin demotion -> 400 Bad Request
	wSelfDemote := httptest.NewRecorder()
	r.ServeHTTP(wSelfDemote, authedReq("PUT", "/users/"+owner.ID, `{"role":"admin"}`, "owner@example.com", "super_admin"))
	if wSelfDemote.Code != http.StatusBadRequest {
		t.Fatalf("self-demotion: want 400, got %d body=%s", wSelfDemote.Code, wSelfDemote.Body.String())
	}
	wLastDemote := httptest.NewRecorder()
	r.ServeHTTP(wLastDemote, authedReq("PUT", "/users/"+owner.ID, `{"role":"admin"}`, "other@example.com", "super_admin"))
	if wLastDemote.Code != http.StatusBadRequest {
		t.Fatalf("last super_admin demotion: want 400, got %d", wLastDemote.Code)
	}

	// 5. Self-deletion -> 400 Bad Request
	wSelfDel := httptest.NewRecorder()
	r.ServeHTTP(wSelfDel, authedReq("DELETE", "/users/"+owner.ID, "", "owner@example.com", "super_admin"))
	if wSelfDel.Code != http.StatusBadRequest {
		t.Fatalf("self-delete: want 400, got %d", wSelfDel.Code)
	}

	// 6. Create a second user, update role + password, then delete
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, authedReq("POST", "/users", `{"email":"ops@example.com","display_name":"Ops","role":"user"}`, "owner@example.com", "super_admin"))
	if w2.Code != http.StatusCreated {
		t.Fatalf("create second user: status %d body=%s", w2.Code, w2.Body.String())
	}
	var ops UserSummary
	_ = json.Unmarshal(w2.Body.Bytes(), &ops)

	wUpd := httptest.NewRecorder()
	r.ServeHTTP(wUpd, authedReq("PUT", "/users/"+ops.ID, `{"role":"admin","password":"new-password-123"}`, "owner@example.com", "super_admin"))
	if wUpd.Code != http.StatusOK {
		t.Fatalf("update ops user: status %d body=%s", wUpd.Code, wUpd.Body.String())
	}
	var opsUpdated UserSummary
	_ = json.Unmarshal(wUpd.Body.Bytes(), &opsUpdated)
	if opsUpdated.Role != "admin" || !opsUpdated.HasPassword || opsUpdated.AuthProvider != "builtin" {
		t.Fatalf("unexpected updated ops user: %+v", opsUpdated)
	}

	wDel := httptest.NewRecorder()
	r.ServeHTTP(wDel, authedReq("DELETE", "/users/"+ops.ID, "", "owner@example.com", "super_admin"))
	if wDel.Code != http.StatusOK {
		t.Fatalf("delete ops user: status %d body=%s", wDel.Code, wDel.Body.String())
	}

	// 7. Verify Audit Log captured user.create, user.update, user.delete and supports filtering
	wAudit := httptest.NewRecorder()
	r.ServeHTTP(wAudit, authedReq("GET", "/audit?target_type=user&search=ops@example.com", "", "owner@example.com", "super_admin"))
	if wAudit.Code != http.StatusOK {
		t.Fatalf("list audit: status %d body=%s", wAudit.Code, wAudit.Body.String())
	}
	var page AuditPage
	if err := json.Unmarshal(wAudit.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 3 || len(page.Entries) != 3 {
		t.Fatalf("expected 3 user audit entries for ops@example.com, got total=%d entries=%+v", page.Total, page.Entries)
	}
	// Ordered newest-first: delete -> update -> create
	if page.Entries[0].Action != "user.delete" || page.Entries[1].Action != "user.update" || page.Entries[2].Action != "user.create" {
		t.Fatalf("unexpected audit ordering: %+v", page.Entries)
	}
}
