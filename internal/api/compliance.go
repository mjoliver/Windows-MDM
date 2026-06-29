package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

// ComplianceRecord is a single policy compliance check result.
type ComplianceRecord struct {
	OMAURI       string `json:"oma_uri"`
	DisplayName  string `json:"display_name"`
	CSPName      string `json:"csp_name"`
	DesiredValue string `json:"desired_value"`
	ActualValue  string `json:"actual_value"`
	IsCompliant  *bool  `json:"is_compliant"` // nil = unknown
	CheckedAt    string `json:"checked_at"`
}

// FleetComplianceSummary gives a high-level fleet overview.
type FleetComplianceSummary struct {
	TotalDevices        int `json:"total_devices"`
	CompliantDevices    int `json:"compliant_devices"`
	NonCompliantDevices int `json:"non_compliant_devices"`
	UnknownDevices      int `json:"unknown_devices"`
	CompliancePercent   int `json:"compliance_percent"`
}

// HandleFleetCompliance returns fleet-wide compliance summary.
// GET /api/compliance
func (h *Handler) HandleFleetCompliance(w http.ResponseWriter, r *http.Request) {
	var summary FleetComplianceSummary

	err := h.db.QueryRowContext(r.Context(), dbpkg.Rebind(`
		SELECT
			COUNT(*) as total,
			SUM(CASE WHEN compliance_status = 'compliant' THEN 1 ELSE 0 END),
			SUM(CASE WHEN compliance_status = 'non_compliant' THEN 1 ELSE 0 END),
			SUM(CASE WHEN compliance_status IN ('unknown','pending') THEN 1 ELSE 0 END)
		FROM devices WHERE is_active = 1
	`)).Scan(&summary.TotalDevices, &summary.CompliantDevices,
		&summary.NonCompliantDevices, &summary.UnknownDevices)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to compute compliance")
		return
	}

	if summary.TotalDevices > 0 {
		summary.CompliancePercent = (summary.CompliantDevices * 100) / summary.TotalDevices
	}

	// Also get the worst-offending policies
	type PolicyIssue struct {
		OMAURI            string `json:"oma_uri"`
		DisplayName       string `json:"display_name"`
		NonCompliantCount int    `json:"non_compliant_count"`
	}

	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT pc.oma_uri, COALESCE(pc.display_name, pc.oma_uri), COUNT(*) as fails
		FROM compliance_records cr
		JOIN policy_catalog pc ON pc.id = cr.catalog_id
		WHERE cr.is_compliant = 0
		GROUP BY cr.catalog_id
		ORDER BY fails DESC
		LIMIT 10
	`))
	var issues []PolicyIssue
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var i PolicyIssue
			if err := rows.Scan(&i.OMAURI, &i.DisplayName, &i.NonCompliantCount); err == nil {
				issues = append(issues, i)
			}
		}
	}
	if issues == nil {
		issues = []PolicyIssue{}
	}

	respondOK(w, map[string]interface{}{
		"summary":    summary,
		"top_issues": issues,
	})
}

// HandleDeviceCompliance returns per-device compliance detail.
// GET /api/compliance/{deviceId}
func (h *Handler) HandleDeviceCompliance(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "deviceId")

	// Check device exists
	var deviceName string
	if err := h.db.QueryRowContext(r.Context(),
		dbpkg.Rebind(`SELECT COALESCE(device_name, id) FROM devices WHERE id = ? AND is_active = 1`), deviceID,
	).Scan(&deviceName); err != nil {
		respondErr(w, http.StatusNotFound, "device not found")
		return
	}

	rows, err := h.db.QueryContext(r.Context(), dbpkg.Rebind(`
		SELECT
			pc.oma_uri,
			COALESCE(pc.display_name, pc.oma_uri),
			COALESCE(pc.csp_name, ''),
			COALESCE(cr.desired_value, ''),
			COALESCE(cr.actual_value, ''),
			cr.is_compliant,
			cr.checked_at
		FROM compliance_records cr
		JOIN policy_catalog pc ON pc.id = cr.catalog_id
		WHERE cr.device_id = ?
		ORDER BY cr.is_compliant ASC, pc.csp_name, pc.display_name
	`), deviceID)
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to load compliance records")
		return
	}
	defer rows.Close()

	var records []ComplianceRecord
	var compliant, nonCompliant, unknown int

	for rows.Next() {
		var rec ComplianceRecord
		var isCompliant *int
		if err := rows.Scan(
			&rec.OMAURI, &rec.DisplayName, &rec.CSPName,
			&rec.DesiredValue, &rec.ActualValue,
			&isCompliant, &rec.CheckedAt,
		); err != nil {
			continue
		}
		if isCompliant != nil {
			v := *isCompliant == 1
			rec.IsCompliant = &v
			if v {
				compliant++
			} else {
				nonCompliant++
			}
		} else {
			unknown++
		}
		records = append(records, rec)
	}

	if records == nil {
		records = []ComplianceRecord{}
	}

	respondOK(w, map[string]interface{}{
		"device_id":     deviceID,
		"device_name":   deviceName,
		"compliant":     compliant,
		"non_compliant": nonCompliant,
		"unknown":       unknown,
		"records":       records,
	})
}
