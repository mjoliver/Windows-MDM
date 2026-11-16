package api

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

var (
	processStartedAt       = time.Now().UTC()
	omadmCheckinsTotal     atomic.Int64
	omadmDurationMillisSum atomic.Int64
)

// RecordOMADMMetric records a completed /omadm SyncML HTTP round-trip for Prometheus & System Status.
func RecordOMADMMetric(duration time.Duration) {
	omadmCheckinsTotal.Add(1)
	ms := duration.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	omadmDurationMillisSum.Add(ms)
}

// SystemStatus summarizes server health, fleet liveness, queue depth, PKI state, and OMA-DM latency.
type SystemStatus struct {
	Status               string    `json:"status"`
	DBDriver             string    `json:"db_driver"`
	DBOK                 bool      `json:"db_ok"`
	CALoaded             bool      `json:"ca_loaded"`
	VaultConfigured      bool      `json:"vault_configured"`
	WNSConfigured        bool      `json:"wns_configured"`
	BackupSupported      bool      `json:"backup_supported"`
	StartedAt            time.Time `json:"started_at"`
	UptimeSeconds        int64     `json:"uptime_seconds"`
	ActiveDevices        int       `json:"active_devices"`
	RetiredDevices       int       `json:"retired_devices"`
	Offline24hDevices    int       `json:"offline_24h_devices"`
	RebootPendingDevices int       `json:"reboot_pending_devices"`
	QueuePending         int       `json:"queue_pending"`
	QueueSent            int       `json:"queue_sent"`
	QueueFailed24h       int       `json:"queue_failed_24h"`
	ActiveCerts          int       `json:"active_certs"`
	ExpiringCerts30d     int       `json:"expiring_certs_30d"`
	RevokedCerts         int       `json:"revoked_certs"`
	OMADMCheckinsTotal   int64     `json:"omadm_checkins_total"`
	OMADMAvgDurationMs   float64   `json:"omadm_avg_duration_ms"`
}

func (h *Handler) collectSystemStatus(r *http.Request) SystemStatus {
	now := time.Now().UTC()
	driver := dbpkg.Driver()
	if driver == "" {
		driver = "sqlite"
	}

	st := SystemStatus{
		Status:             "healthy",
		DBDriver:           driver,
		DBOK:               h.db != nil && h.db.PingContext(r.Context()) == nil,
		CALoaded:           h.ca != nil && h.ca.RootCert() != nil,
		VaultConfigured:    h.vault != nil,
		WNSConfigured:      h.wns != nil && h.wns.Enabled(),
		BackupSupported:    driver == "sqlite",
		StartedAt:          processStartedAt,
		UptimeSeconds:      int64(now.Sub(processStartedAt).Seconds()),
		OMADMCheckinsTotal: omadmCheckinsTotal.Load(),
	}
	if !st.DBOK {
		st.Status = "degraded"
		return st
	}

	if st.OMADMCheckinsTotal > 0 {
		st.OMADMAvgDurationMs = float64(omadmDurationMillisSum.Load()) / float64(st.OMADMCheckinsTotal)
	}

	cutoff24h := now.Add(-24 * time.Hour)
	_ = h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT
			COALESCE(SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN is_active = 0 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN is_active = 1 AND (last_checkin IS NULL OR last_checkin < ?) THEN 1 ELSE 0 END), 0)
		FROM devices
	`), cutoff24h).Scan(&st.ActiveDevices, &st.RetiredDevices, &st.Offline24hDevices)

	_ = h.db.QueryRowContext(r.Context(), `
		SELECT COALESCE(SUM(CASE WHEN dp.reboot_required = 1 THEN 1 ELSE 0 END), 0)
		FROM device_posture dp
		JOIN devices d ON d.id = dp.device_id
		WHERE d.is_active = 1
	`).Scan(&st.RebootPendingDevices)

	_ = h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT
			COALESCE(SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'failed' AND completed_at >= ? THEN 1 ELSE 0 END), 0)
		FROM command_queue
	`), cutoff24h).Scan(&st.QueuePending, &st.QueueSent, &st.QueueFailed24h)

	soon30d := now.Add(30 * 24 * time.Hour)
	_ = h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT
			COALESCE(SUM(CASE WHEN revoked = 0 AND not_after > ? THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN revoked = 0 AND not_after > ? AND not_after <= ? THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN revoked = 1 THEN 1 ELSE 0 END), 0)
		FROM certificates
		WHERE cert_type <> 'root_ca'
	`), now, now, soon30d).Scan(&st.ActiveCerts, &st.ExpiringCerts30d, &st.RevokedCerts)

	return st
}

// HandleSystemStatus returns operational health and fleet telemetry JSON.
// GET /api/system/status
func (h *Handler) HandleSystemStatus(w http.ResponseWriter, r *http.Request) {
	respondOK(w, h.collectSystemStatus(r))
}

// HandlePrometheusMetrics serves Prometheus text exposition format v0.0.4 metrics.
// GET /api/system/metrics
func (h *Handler) HandlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	st := h.collectSystemStatus(r)

	var compCompliant, compNonCompliant, compPending, compUnknown int
	_ = h.db.QueryRowContext(r.Context(), `
		SELECT
			COALESCE(SUM(CASE WHEN compliance_status = 'compliant' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN compliance_status = 'non_compliant' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN compliance_status = 'pending' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN compliance_status NOT IN ('compliant', 'non_compliant', 'pending') THEN 1 ELSE 0 END), 0)
		FROM devices WHERE is_active = 1
	`).Scan(&compCompliant, &compNonCompliant, &compPending, &compUnknown)

	var qSuccess, qFailed int
	_ = h.db.QueryRowContext(r.Context(), `
		SELECT
			COALESCE(SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0)
		FROM command_queue
	`).Scan(&qSuccess, &qFailed)

	var whOK, whFail int
	_ = h.db.QueryRowContext(r.Context(), `
		SELECT
			COALESCE(SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END), 0)
		FROM webhook_deliveries
	`).Scan(&whOK, &whFail)

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	up := 0
	if st.DBOK {
		up = 1
	}

	var b strings.Builder
	b.WriteString("# HELP latchz_up Whether the Latchz MDM server and database are healthy (1 = healthy).\n")
	b.WriteString("# TYPE latchz_up gauge\n")
	fmt.Fprintf(&b, "latchz_up %d\n", up)

	b.WriteString("# HELP latchz_uptime_seconds Process uptime in seconds.\n")
	b.WriteString("# TYPE latchz_uptime_seconds counter\n")
	fmt.Fprintf(&b, "latchz_uptime_seconds %d\n", st.UptimeSeconds)

	b.WriteString("# HELP latchz_devices_total Enrolled Windows devices by lifecycle state.\n")
	b.WriteString("# TYPE latchz_devices_total gauge\n")
	fmt.Fprintf(&b, "latchz_devices_total{state=\"active\"} %d\n", st.ActiveDevices)
	fmt.Fprintf(&b, "latchz_devices_total{state=\"retired\"} %d\n", st.RetiredDevices)

	b.WriteString("# HELP latchz_devices_offline_24h_total Active devices with no check-in in the past 24 hours.\n")
	b.WriteString("# TYPE latchz_devices_offline_24h_total gauge\n")
	fmt.Fprintf(&b, "latchz_devices_offline_24h_total %d\n", st.Offline24hDevices)

	b.WriteString("# HELP latchz_devices_reboot_pending_total Active devices reporting RebootRequired=true.\n")
	b.WriteString("# TYPE latchz_devices_reboot_pending_total gauge\n")
	fmt.Fprintf(&b, "latchz_devices_reboot_pending_total %d\n", st.RebootPendingDevices)

	b.WriteString("# HELP latchz_devices_compliance_total Active devices by compliance status.\n")
	b.WriteString("# TYPE latchz_devices_compliance_total gauge\n")
	fmt.Fprintf(&b, "latchz_devices_compliance_total{status=\"compliant\"} %d\n", compCompliant)
	fmt.Fprintf(&b, "latchz_devices_compliance_total{status=\"non_compliant\"} %d\n", compNonCompliant)
	fmt.Fprintf(&b, "latchz_devices_compliance_total{status=\"pending\"} %d\n", compPending)
	fmt.Fprintf(&b, "latchz_devices_compliance_total{status=\"unknown\"} %d\n", compUnknown)

	b.WriteString("# HELP latchz_command_queue_total OMA-DM command queue rows by status.\n")
	b.WriteString("# TYPE latchz_command_queue_total gauge\n")
	fmt.Fprintf(&b, "latchz_command_queue_total{status=\"pending\"} %d\n", st.QueuePending)
	fmt.Fprintf(&b, "latchz_command_queue_total{status=\"sent\"} %d\n", st.QueueSent)
	fmt.Fprintf(&b, "latchz_command_queue_total{status=\"success\"} %d\n", qSuccess)
	fmt.Fprintf(&b, "latchz_command_queue_total{status=\"failed\"} %d\n", qFailed)

	b.WriteString("# HELP latchz_certificates_total Leaf X.509 certificates by state.\n")
	b.WriteString("# TYPE latchz_certificates_total gauge\n")
	fmt.Fprintf(&b, "latchz_certificates_total{state=\"active\"} %d\n", st.ActiveCerts)
	fmt.Fprintf(&b, "latchz_certificates_total{state=\"expiring_30d\"} %d\n", st.ExpiringCerts30d)
	fmt.Fprintf(&b, "latchz_certificates_total{state=\"revoked\"} %d\n", st.RevokedCerts)

	b.WriteString("# HELP latchz_omadm_checkins_total Total OMA-DM SyncML HTTP check-ins processed.\n")
	b.WriteString("# TYPE latchz_omadm_checkins_total counter\n")
	fmt.Fprintf(&b, "latchz_omadm_checkins_total %d\n", st.OMADMCheckinsTotal)

	b.WriteString("# HELP latchz_omadm_duration_ms_sum Cumulative OMA-DM SyncML handler duration in milliseconds.\n")
	b.WriteString("# TYPE latchz_omadm_duration_ms_sum counter\n")
	fmt.Fprintf(&b, "latchz_omadm_duration_ms_sum %d\n", omadmDurationMillisSum.Load())

	b.WriteString("# HELP latchz_webhook_deliveries_total Outbound webhook delivery attempts by result.\n")
	b.WriteString("# TYPE latchz_webhook_deliveries_total counter\n")
	fmt.Fprintf(&b, "latchz_webhook_deliveries_total{result=\"success\"} %d\n", whOK)
	fmt.Fprintf(&b, "latchz_webhook_deliveries_total{result=\"failed\"} %d\n", whFail)

	b.WriteString("# HELP latchz_go_goroutines Current Go runtime goroutines.\n")
	b.WriteString("# TYPE latchz_go_goroutines gauge\n")
	fmt.Fprintf(&b, "latchz_go_goroutines %d\n", runtime.NumGoroutine())

	b.WriteString("# HELP latchz_go_mem_alloc_bytes Current Go heap bytes allocated.\n")
	b.WriteString("# TYPE latchz_go_mem_alloc_bytes gauge\n")
	fmt.Fprintf(&b, "latchz_go_mem_alloc_bytes %d\n", mem.Alloc)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

// HandleDownloadBackup creates a consistent online SQLite snapshot via VACUUM INTO
// and streams it as a downloadable .sqlite3 disaster-recovery archive.
// GET /api/system/backup
func (h *Handler) HandleDownloadBackup(w http.ResponseWriter, r *http.Request) {
	actor := emailFromCtx(r)
	if strings.HasPrefix(actor, "apikey:") {
		respondErr(w, http.StatusForbidden, "interactive administrator session required to download database backups")
		return
	}

	driver := dbpkg.Driver()
	if driver != "" && driver != "sqlite" {
		respondErr(w, http.StatusNotImplemented, "online file backup requires SQLite (use pg_dump for PostgreSQL)")
		return
	}

	tmpFile := filepath.Join(os.TempDir(), "latchz-backup-"+uuid.NewString()+".sqlite3")
	defer os.Remove(tmpFile)

	// Escape single quotes in file path for SQLite VACUUM INTO literal.
	escapedPath := strings.ReplaceAll(filepath.ToSlash(tmpFile), "'", "''")
	if _, err := h.db.ExecContext(r.Context(), fmt.Sprintf("VACUUM INTO '%s'", escapedPath)); err != nil {
		slog.Error("api: SQLite VACUUM INTO backup failed", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to create online SQLite snapshot")
		return
	}

	f, err := os.Open(tmpFile)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to open backup snapshot")
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to stat backup snapshot")
		return
	}

	filename := fmt.Sprintf("latchz-backup-%s.sqlite3", time.Now().UTC().Format("20060102-150405"))
	h.audit(r, actor, "system.backup_download", "system", "database",
		fmt.Sprintf(`{"filename":%q,"bytes":%d}`, filename, stat.Size()))

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}
