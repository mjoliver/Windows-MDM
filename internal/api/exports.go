package api

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// sanitizeCSVCell guards against spreadsheet formula injection when opened in Excel/Sheets.
func sanitizeCSVCell(v string) string {
	if v == "" {
		return ""
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + v
	default:
		return v
	}
}

// ExportedDeviceRow represents one device row in fleet CSV/JSON exports.
type ExportedDeviceRow struct {
	ID               string     `json:"id"`
	DeviceName       string     `json:"device_name"`
	SerialNumber     string     `json:"serial_number"`
	HardwareID       string     `json:"hardware_id"`
	Manufacturer     string     `json:"manufacturer"`
	Model            string     `json:"model"`
	OSVersion        string     `json:"os_version"`
	OSBuild          string     `json:"os_build"`
	ComplianceStatus string     `json:"compliance_status"`
	EnrollmentState  string     `json:"enrollment_state"`
	IsActive         bool       `json:"is_active"`
	EnrolledBy       string     `json:"enrolled_by"`
	EnrolledAt       time.Time  `json:"enrolled_at"`
	LastCheckin      *time.Time `json:"last_checkin"`
	TotalRAMMB       *int64     `json:"total_ram_mb"`
	TotalStorageMB   *int64     `json:"total_storage_mb"`
	FreeStorageMB    *int64     `json:"free_storage_mb"`
	TPMVersion       string     `json:"tpm_version"`
	SecureBoot       *bool      `json:"secure_boot"`
	BitLockerActive  *bool      `json:"bitlocker_encrypted"`
	DefenderActive   *bool      `json:"defender_active"`
	FirewallActive   *bool      `json:"firewall_active"`
}

// ExportedSoftwareRow represents one discovered program row across the fleet.
type ExportedSoftwareRow struct {
	DeviceID     string    `json:"device_id"`
	DeviceName   string    `json:"device_name"`
	SerialNumber string    `json:"serial_number"`
	AppName      string    `json:"app_name"`
	Version      string    `json:"version"`
	Publisher    string    `json:"publisher"`
	Source       string    `json:"source"`
	InstallDate  string    `json:"install_date"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func nullIntToBoolPtr(n sql.NullInt64, okFn func(int64) bool) *bool {
	if !n.Valid {
		return nil
	}
	v := okFn(n.Int64)
	return &v
}

func boolPtrCSV(p *bool) string {
	if p == nil {
		return ""
	}
	if *p {
		return "true"
	}
	return "false"
}

func intPtrCSV(p *int64) string {
	if p == nil {
		return ""
	}
	return strconv.FormatInt(*p, 10)
}

// HandleExportDevices streams the full fleet hardware & security posture inventory as CSV or JSON.
// GET /api/export/devices?format=csv|json
func (h *Handler) HandleExportDevices(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "json" {
		respondErr(w, http.StatusBadRequest, "format must be csv or json")
		return
	}

	rows, err := h.db.QueryContext(r.Context(), `
		SELECT d.id, COALESCE(d.device_name,''), COALESCE(d.serial_number,''), d.hardware_id,
		       COALESCE(d.manufacturer,''), COALESCE(d.model,''),
		       COALESCE(d.os_version,''), COALESCE(d.os_build,''),
		       d.compliance_status, COALESCE(d.enrollment_state,'enrolled'), d.is_active,
		       COALESCE(d.enrolled_by,''), d.enrolled_at, d.last_checkin,
		       dp.total_ram_mb, dp.total_storage_mb, dp.free_storage_mb,
		       COALESCE(dp.tpm_version,''), dp.secure_boot_state,
		       dp.encryption_status, dp.antivirus_status, dp.firewall_status
		FROM devices d
		LEFT JOIN device_posture dp ON dp.device_id = d.id
		ORDER BY d.is_active DESC, d.enrolled_at DESC
	`)
	if err != nil {
		slog.Error("api: exporting devices", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to export devices")
		return
	}
	defer rows.Close()

	items := []ExportedDeviceRow{}
	for rows.Next() {
		var it ExportedDeviceRow
		var isActive int
		var ramMB, totalMB, freeMB, secBoot, encSt, avSt, fwSt sql.NullInt64
		if err := rows.Scan(
			&it.ID, &it.DeviceName, &it.SerialNumber, &it.HardwareID,
			&it.Manufacturer, &it.Model, &it.OSVersion, &it.OSBuild,
			&it.ComplianceStatus, &it.EnrollmentState, &isActive,
			&it.EnrolledBy, &it.EnrolledAt, &it.LastCheckin,
			&ramMB, &totalMB, &freeMB, &it.TPMVersion, &secBoot, &encSt, &avSt, &fwSt,
		); err != nil {
			continue
		}
		it.IsActive = isActive != 0
		if ramMB.Valid {
			v := ramMB.Int64
			it.TotalRAMMB = &v
		}
		if totalMB.Valid {
			v := totalMB.Int64
			it.TotalStorageMB = &v
		}
		if freeMB.Valid {
			v := freeMB.Int64
			it.FreeStorageMB = &v
		}
		it.SecureBoot = nullIntToBoolPtr(secBoot, func(v int64) bool { return v == 1 })
		it.BitLockerActive = nullIntToBoolPtr(encSt, func(v int64) bool { return v == 0 })
		it.DefenderActive = nullIntToBoolPtr(avSt, func(v int64) bool { return v > 0 })
		it.FirewallActive = nullIntToBoolPtr(fwSt, func(v int64) bool { return v > 0 })
		items = append(items, it)
	}

	ts := time.Now().UTC().Format("20060102")
	if format == "json" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="latchz-devices-%s.json"`, ts))
		respondOK(w, items)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="latchz-devices-%s.csv"`, ts))
	w.WriteHeader(http.StatusOK)

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"device_id", "device_name", "serial_number", "hardware_id",
		"manufacturer", "model", "os_version", "os_build",
		"compliance_status", "enrollment_state", "is_active",
		"enrolled_by", "enrolled_at", "last_checkin",
		"total_ram_mb", "total_storage_mb", "free_storage_mb",
		"tpm_version", "secure_boot", "bitlocker_encrypted",
		"defender_active", "firewall_active",
	})
	for _, d := range items {
		lastStr := ""
		if d.LastCheckin != nil {
			lastStr = d.LastCheckin.UTC().Format(time.RFC3339)
		}
		_ = cw.Write([]string{
			sanitizeCSVCell(d.ID),
			sanitizeCSVCell(d.DeviceName),
			sanitizeCSVCell(d.SerialNumber),
			sanitizeCSVCell(d.HardwareID),
			sanitizeCSVCell(d.Manufacturer),
			sanitizeCSVCell(d.Model),
			sanitizeCSVCell(d.OSVersion),
			sanitizeCSVCell(d.OSBuild),
			sanitizeCSVCell(d.ComplianceStatus),
			sanitizeCSVCell(d.EnrollmentState),
			strconv.FormatBool(d.IsActive),
			sanitizeCSVCell(d.EnrolledBy),
			d.EnrolledAt.UTC().Format(time.RFC3339),
			lastStr,
			intPtrCSV(d.TotalRAMMB),
			intPtrCSV(d.TotalStorageMB),
			intPtrCSV(d.FreeStorageMB),
			sanitizeCSVCell(d.TPMVersion),
			boolPtrCSV(d.SecureBoot),
			boolPtrCSV(d.BitLockerActive),
			boolPtrCSV(d.DefenderActive),
			boolPtrCSV(d.FirewallActive),
		})
	}
	cw.Flush()
}

// HandleExportSoftware streams the fleet-wide discovered Win32/MSI software inventory as CSV or JSON.
// GET /api/export/software?format=csv|json
func (h *Handler) HandleExportSoftware(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "json" {
		respondErr(w, http.StatusBadRequest, "format must be csv or json")
		return
	}

	rows, err := h.db.QueryContext(r.Context(), `
		SELECT s.device_id, COALESCE(d.device_name,''), COALESCE(d.serial_number,''),
		       s.name, COALESCE(s.version,''), COALESCE(s.publisher,''),
		       COALESCE(s.source,''), COALESCE(s.install_date,''), s.updated_at
		FROM device_software_inventory s
		JOIN devices d ON d.id = s.device_id
		WHERE d.is_active = 1
		ORDER BY d.device_name ASC, s.name ASC
	`)
	if err != nil {
		slog.Error("api: exporting software inventory", "err", err)
		respondErr(w, http.StatusInternalServerError, "failed to export software inventory")
		return
	}
	defer rows.Close()

	items := []ExportedSoftwareRow{}
	for rows.Next() {
		var it ExportedSoftwareRow
		if err := rows.Scan(
			&it.DeviceID, &it.DeviceName, &it.SerialNumber,
			&it.AppName, &it.Version, &it.Publisher,
			&it.Source, &it.InstallDate, &it.UpdatedAt,
		); err != nil {
			continue
		}
		items = append(items, it)
	}

	ts := time.Now().UTC().Format("20060102")
	if format == "json" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="latchz-software-%s.json"`, ts))
		respondOK(w, items)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="latchz-software-%s.csv"`, ts))
	w.WriteHeader(http.StatusOK)

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"device_id", "device_name", "serial_number",
		"app_name", "version", "publisher", "source", "install_date", "updated_at",
	})
	for _, s := range items {
		_ = cw.Write([]string{
			sanitizeCSVCell(s.DeviceID),
			sanitizeCSVCell(s.DeviceName),
			sanitizeCSVCell(s.SerialNumber),
			sanitizeCSVCell(s.AppName),
			sanitizeCSVCell(s.Version),
			sanitizeCSVCell(s.Publisher),
			sanitizeCSVCell(s.Source),
			sanitizeCSVCell(s.InstallDate),
			s.UpdatedAt.UTC().Format(time.RFC3339),
		})
	}
	cw.Flush()
}
