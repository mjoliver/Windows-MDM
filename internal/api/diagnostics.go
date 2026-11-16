package api

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/mdm"
)

// CSPExplorerQueryItem represents a single live OMA-URI Get inspection on a device.
type CSPExplorerQueryItem struct {
	ID          string     `json:"id"`
	DeviceID    string     `json:"device_id"`
	QueueID     int64      `json:"queue_id"`
	Label       string     `json:"label"`
	OMAURI      string     `json:"oma_uri"`
	Status      string     `json:"status"`
	ResultCode  string     `json:"result_code"`
	ResultData  string     `json:"result_data"`
	QueriedBy   string     `json:"queried_by"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at"`
}

// HandleGetDeviceCSPExplorer returns official read-only CSP presets and recent inspection results for a device.
// GET /api/devices/{id}/csp-explorer
func (h *Handler) HandleGetDeviceCSPExplorer(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.getDevice(r, id); errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT
			q.id, q.device_id, COALESCE(q.queue_id, 0), q.label, q.oma_uri,
			CASE
				WHEN q.status IN ('success', 'failed') THEN q.status
				ELSE COALESCE(cq.status, q.status)
			END,
			CASE WHEN COALESCE(q.result_code, '') <> '' THEN q.result_code ELSE COALESCE(cq.result_code, '') END,
			CASE WHEN COALESCE(q.result_data, '') <> '' THEN q.result_data ELSE COALESCE(cq.result_data, '') END,
			q.queried_by, q.created_at,
			q.completed_at, cq.completed_at
		FROM device_csp_queries q
		LEFT JOIN command_queue cq ON cq.id = q.queue_id
		WHERE q.device_id = ?
		ORDER BY q.created_at DESC, q.id DESC
		LIMIT 50
	`), id)
	if err != nil {
		slog.Error("api: listing device csp explorer queries", "device_id", id, "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to load CSP explorer history")
		return
	}
	defer rows.Close()

	queries := []CSPExplorerQueryItem{}
	for rows.Next() {
		var it CSPExplorerQueryItem
		var qCompAt, cqCompAt sql.NullTime
		if err := rows.Scan(
			&it.ID, &it.DeviceID, &it.QueueID, &it.Label, &it.OMAURI,
			&it.Status, &it.ResultCode, &it.ResultData,
			&it.QueriedBy, &it.CreatedAt, &qCompAt, &cqCompAt,
		); err != nil {
			continue
		}
		if qCompAt.Valid {
			t := qCompAt.Time
			it.CompletedAt = &t
		} else if cqCompAt.Valid {
			t := cqCompAt.Time
			it.CompletedAt = &t
		}
		queries = append(queries, it)
	}

	respondOK(w, map[string]interface{}{
		"presets": mdm.OfficialCSPPresets,
		"queries": queries,
	})
}

// HandleCreateDeviceCSPQuery queues an ad-hoc read-only OMA-DM Get command for live CSP inspection.
// POST /api/devices/{id}/csp-explorer
func (h *Handler) HandleCreateDeviceCSPQuery(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := emailFromCtx(r)

	var body struct {
		OMAURI string `json:"oma_uri"`
		Label  string `json:"label"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	cleanURI, err := mdm.ValidateCSPExplorerURI(body.OMAURI)
	if err != nil {
		respondErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if _, err := h.getDevice(r, id); errors.Is(err, sql.ErrNoRows) {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		respondErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	label := strings.TrimSpace(body.Label)
	if len(label) > 100 {
		label = label[:100]
	}
	if label == "" {
		for _, p := range mdm.OfficialCSPPresets {
			if strings.EqualFold(p.OMAURI, cleanURI) {
				label = p.Label
				break
			}
		}
	}

	queueID, err := mdm.EnqueueGet(h.db, id, cleanURI)
	if err != nil {
		slog.Error("api: queueing csp explorer Get", "device_id", id, "uri", cleanURI, "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to queue CSP Get command")
		return
	}

	queryID := uuid.NewString()
	now := time.Now().UTC()
	_, err = h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		INSERT INTO device_csp_queries (
			id, device_id, queue_id, label, oma_uri, status, result_code, result_data, queried_by, created_at
		) VALUES (?, ?, ?, ?, ?, 'pending', '', '', ?, ?)
	`), queryID, id, queueID, label, cleanURI, actor, now)
	if err != nil {
		slog.Error("api: inserting device_csp_queries row", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to record CSP query")
		return
	}

	h.wakeDevice(id)
	h.audit(r, actor, "device.csp_query", "device", id, fmt.Sprintf(`{"oma_uri":%q,"queue_id":%d}`, cleanURI, queueID))

	respondCreated(w, CSPExplorerQueryItem{
		ID:        queryID,
		DeviceID:  id,
		QueueID:   queueID,
		Label:     label,
		OMAURI:    cleanURI,
		Status:    "pending",
		QueriedBy: actor,
		CreatedAt: now,
	})
}

// HandleDeleteDeviceCSPQuery removes a CSP Explorer history entry.
// DELETE /api/devices/{id}/csp-explorer/{queryId}
func (h *Handler) HandleDeleteDeviceCSPQuery(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	queryID := chi.URLParam(r, "queryId")

	res, err := h.db.ExecContext(r.Context(), dbpkg.Rebind(`
		DELETE FROM device_csp_queries WHERE id = ? AND device_id = ?
	`), queryID, id)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to delete CSP query")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		respondErr(w, http.StatusNotFound, "CSP query not found")
		return
	}
	respondOK(w, map[string]interface{}{"deleted": true, "id": queryID})
}
