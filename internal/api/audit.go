package api

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

// AuditEntry represents a single row in the audit_log table.
type AuditEntry struct {
	ID         int       `json:"id"`
	UserEmail  string    `json:"user_email"`
	Action     string    `json:"action"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	Details    string    `json:"details"`
	IPAddress  string    `json:"ip_address"`
	CreatedAt  time.Time `json:"created_at"`
}

// AuditPage is a paginated list of audit log entries.
type AuditPage struct {
	Entries []AuditEntry `json:"entries"`
	Total   int          `json:"total"`
	Limit   int          `json:"limit"`
	Offset  int          `json:"offset"`
}

// HandleListAudit returns a filtered, paginated view of the administrative audit log.
// GET /api/audit
func (h *Handler) HandleListAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	search := strings.TrimSpace(q.Get("search"))
	action := strings.TrimSpace(q.Get("action"))
	targetType := strings.TrimSpace(q.Get("target_type"))

	limit := 50
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
		if l > 200 {
			l = 200
		}
		limit = l
	}
	offset := 0
	if o, err := strconv.Atoi(q.Get("offset")); err == nil && o >= 0 {
		offset = o
	}

	var clauses []string
	var args []interface{}

	if targetType != "" {
		clauses = append(clauses, "target_type = ?")
		args = append(args, targetType)
	}
	if action != "" {
		clauses = append(clauses, "action = ?")
		args = append(args, action)
	}
	if search != "" {
		pat := "%" + strings.ToLower(search) + "%"
		clauses = append(clauses, "(LOWER(COALESCE(user_email,'')) LIKE ? OR LOWER(action) LIKE ? OR LOWER(COALESCE(target_id,'')) LIKE ? OR LOWER(COALESCE(details,'')) LIKE ?)")
		args = append(args, pat, pat, pat, pat)
	}

	whereSQL := ""
	if len(clauses) > 0 {
		whereSQL = " WHERE " + strings.Join(clauses, " AND ")
	}

	var total int
	countQuery := dbpkg.Rebind("SELECT COUNT(*) FROM audit_log" + whereSQL)
	if err := h.db.QueryRowContext(r.Context(), countQuery, args...).Scan(&total); err != nil {
		slog.Error("api: counting audit log", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to query audit log")
		return
	}

	listArgs := append(append([]interface{}{}, args...), limit, offset)
	listQuery := dbpkg.Rebind(`
		SELECT id, COALESCE(user_email,''), action, COALESCE(target_type,''),
		       COALESCE(target_id,''), COALESCE(details,''), COALESCE(ip_address,''), created_at
		FROM audit_log` + whereSQL + `
		ORDER BY id DESC
		LIMIT ? OFFSET ?
	`)

	rows, err := h.db.QueryContext(r.Context(), listQuery, listArgs...)
	if err != nil {
		slog.Error("api: listing audit log", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to list audit log")
		return
	}
	defer rows.Close()

	entries := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(
			&e.ID, &e.UserEmail, &e.Action, &e.TargetType,
			&e.TargetID, &e.Details, &e.IPAddress, &e.CreatedAt,
		); err != nil {
			slog.Error("api: scanning audit log row", "err", err)
			continue
		}
		entries = append(entries, e)
	}

	respondOK(w, AuditPage{
		Entries: entries,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
	})
}
