package mdm

import (
	"database/sql"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

// Session lifetime bounds. Sessions are short-lived; abandoned ones are reaped
// so the in-memory map cannot grow without bound (memory DoS).
const (
	sessionTTL    = 30 * time.Minute
	sweepInterval = 1 * time.Minute
	// maxInterrogations caps device-info Get rounds per session so a device that
	// never reports complete info does not get re-interrogated forever.
	maxInterrogations = 3
)

// sessionStore tracks active OMA-DM sessions in memory.
// Each session is identified by (deviceID + sessionID).
// Sessions are short-lived — a device connects, we exchange a few messages, it disconnects.
type sessionStore struct {
	mu        sync.Mutex
	sessions  map[string]*Session
	lastSweep time.Time
}

// newSessionStore creates an empty session store. Each mdm.Handler owns one so
// state does not leak across servers (or across tests).
func newSessionStore() *sessionStore {
	return &sessionStore{sessions: make(map[string]*Session), lastSweep: time.Now()}
}

// Session tracks the state of a single OMA-DM management session.
//
// A single OMA-DM session can span multiple TCP connections (and thus multiple
// concurrent HTTP requests). All mutable fields below are guarded by mu; callers
// must hold it for the duration of request processing for a given session.
type Session struct {
	mu             sync.Mutex
	DeviceID       string
	SessionID      string
	NextMsgID      int
	NextCmdID      int
	IsFirst        bool // first session after enrollment (alert 1200)
	Interrogations int  // device-info Get rounds issued this session
	StartedAt      time.Time
	LastSeen       time.Time
	CmdMap         map[string]int // maps CmdID (from SyncML) -> queueID (from DB)
}

// get retrieves or creates a session for the given device+session key.
func (s *sessionStore) get(deviceID, sessionID string, isFirst bool) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sweepLocked()

	key := deviceID + ":" + sessionID
	sess, ok := s.sessions[key]
	if !ok {
		sess = &Session{
			DeviceID:  deviceID,
			SessionID: sessionID,
			NextMsgID: 1,
			NextCmdID: 2, // 1 is reserved for status ACKs
			IsFirst:   isFirst,
			StartedAt: time.Now(),
			LastSeen:  time.Now(),
			CmdMap:    make(map[string]int),
		}
		s.sessions[key] = sess
		slog.Info("mdm: new session", "device_id", deviceID, "session_id", sessionID, "first", isFirst)
	}
	sess.LastSeen = time.Now()
	return sess
}

// remove ends the session (called after Final is exchanged).
func (s *sessionStore) remove(deviceID, sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, deviceID+":"+sessionID)
}

// sweepLocked evicts sessions idle longer than sessionTTL. Throttled to run at
// most once per sweepInterval. Caller must hold s.mu.
func (s *sessionStore) sweepLocked() {
	now := time.Now()
	if now.Sub(s.lastSweep) < sweepInterval {
		return
	}
	s.lastSweep = now
	for key, sess := range s.sessions {
		if now.Sub(sess.LastSeen) > sessionTTL {
			delete(s.sessions, key)
		}
	}
}

// nextCmdID returns the next available command ID and advances the counter.
func (s *Session) nextCmdID() string {
	id := strconv.Itoa(s.NextCmdID)
	s.NextCmdID++
	return id
}

// ── Device record updates ─────────────────────────────────────────────────────

// updateDeviceFromResults processes OMA-DM Results elements and updates
// the device record and compliance tables in the database.
func updateDeviceFromResults(db *sql.DB, deviceID string, sess *Session, results []Results) {
	if len(results) == 0 {
		return
	}

	updates := make(map[string]string)
	for _, r := range results {
		// Map back to our command queue if possible
		queueID, ok := sess.CmdMap[r.CmdRef]

		var payload strings.Builder
		for _, item := range r.Items {
			if item.Source != nil && item.Data != "" {
				updates[item.Source.LocURI] = item.Data
				if ok {
					payload.WriteString(item.Data)
					payload.WriteString("\n")
				}
			}
		}

		if ok && payload.Len() > 0 {
			_, _ = db.Exec(dbpkg.Rebind(`UPDATE command_queue SET result_data = ? WHERE id = ?`), payload.String(), queueID)
		}
	}

	if len(updates) == 0 {
		return
	}

	// Map OMA-URIs to device table columns
	updateDevice(db, deviceID, updates)

	// The rest go to compliance_records
	updateCompliance(db, deviceID, updates)
}

func updateDevice(db *sql.DB, deviceID string, values map[string]string) {
	// Build a partial update from known device-info URIs
	type colVal struct{ col, val string }
	var sets []colVal

	for uri, val := range values {
		switch uri {
		case OMADevDetailSwV:
			sets = append(sets, colVal{"os_version", val})
			// If it looks like 10.0.22621.1, the build info is included in the version string.
			// Extract everything after "10.0." as the build.
			if strings.HasPrefix(val, "10.0.") {
				build := strings.TrimPrefix(val, "10.0.")
				sets = append(sets, colVal{"os_build", build})
			}
		case OMADevDetailOSPlatform:
			// combine with existing
		case OMADevDetailOSBuild:
			sets = append(sets, colVal{"os_build", val})
		case OMADevDetailComputerName:
			sets = append(sets, colVal{"device_name", val})
		case OMADevInfoMan:
			sets = append(sets, colVal{"manufacturer", val})
		case OMADevInfoMod:
			sets = append(sets, colVal{"model", val})
		}
	}

	if len(sets) == 0 {
		return
	}

	// Build SET clause
	query := "UPDATE devices SET last_checkin = CURRENT_TIMESTAMP"
	args := []interface{}{}
	for _, sv := range sets {
		query += fmt.Sprintf(", %s = ?", sv.col)
		args = append(args, sv.val)
	}
	query += " WHERE id = ?"
	args = append(args, deviceID)

	if _, err := db.Exec(dbpkg.Rebind(query), args...); err != nil {
		slog.Error("mdm: updating device record from check-in results", "device_id", deviceID, "err", err)
	}
}

func updateCompliance(db *sql.DB, deviceID string, values map[string]string) {
	// Look up policy catalog entries matching the reported URIs
	for uri, actualValue := range values {
		// Ensure URI has leading ./ to match the catalog
		if !strings.HasPrefix(uri, "./") {
			uri = "./" + uri
		}

		var catalogID int
		err := db.QueryRow(
			dbpkg.Rebind(`SELECT id FROM policy_catalog WHERE oma_uri = ?`), uri,
		).Scan(&catalogID)

		if err == sql.ErrNoRows {
			continue // URI not in our policy catalog (e.g. device info URIs)
		}
		if err != nil {
			slog.Error("mdm: looking up catalog entry", "uri", uri, "err", err)
			continue
		}

		// Get the desired value from any applied profile
		var desiredValue sql.NullString
		_ = db.QueryRow(dbpkg.Rebind(`
			SELECT ps.desired_value
			FROM profile_settings ps
			JOIN group_profiles gp ON gp.profile_id = ps.profile_id
			JOIN device_group_members dgm ON dgm.group_id = gp.group_id
			WHERE dgm.device_id = ? AND ps.catalog_id = ?
			LIMIT 1
		`), deviceID, catalogID).Scan(&desiredValue)

		isCompliant := sql.NullBool{Valid: false}
		if desiredValue.Valid {
			isCompliant = sql.NullBool{
				Bool:  desiredValue.String == actualValue,
				Valid: true,
			}
		}

		_, err = db.Exec(dbpkg.Rebind(`
			INSERT INTO compliance_records (device_id, catalog_id, desired_value, actual_value, is_compliant)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (device_id, catalog_id) DO UPDATE SET
				desired_value = EXCLUDED.desired_value,
				actual_value = EXCLUDED.actual_value,
				is_compliant = EXCLUDED.is_compliant,
				checked_at = CURRENT_TIMESTAMP
		`), deviceID, catalogID, desiredValue.String, actualValue, isCompliant.Bool)
		if err != nil {
			slog.Error("mdm: recording compliance value", "device_id", deviceID, "uri", uri, "err", err)
		}
	}

	// Update overall device compliance status
	refreshDeviceCompliance(db, deviceID)
}

// refreshDeviceCompliance recalculates and updates the device's overall compliance status.
func refreshDeviceCompliance(db *sql.DB, deviceID string) {
	var total, compliant int
	err := db.QueryRow(dbpkg.Rebind(`
		SELECT
			COUNT(*) as total,
			SUM(CASE WHEN is_compliant = 1 THEN 1 ELSE 0 END) as compliant
		FROM compliance_records
		WHERE device_id = ? AND is_compliant IS NOT NULL
	`), deviceID).Scan(&total, &compliant)
	if err != nil || total == 0 {
		return
	}

	status := "non_compliant"
	if compliant == total {
		status = "compliant"
	} else if compliant > 0 {
		status = "non_compliant" // partial — still non-compliant
	}

	_, _ = db.Exec(
		dbpkg.Rebind(`UPDATE devices SET compliance_status = ? WHERE id = ?`),
		status, deviceID,
	)
}
