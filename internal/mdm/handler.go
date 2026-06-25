package mdm

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

// Handler handles OMA-DM SyncML check-ins from enrolled devices.
type Handler struct {
	db     *sql.DB
	ca     *x509.CertPool // root CA pool for mTLS device auth
	domain string
	store  *sessionStore
}

// NewHandler creates an OMA-DM handler.
func NewHandler(db *sql.DB, caPool *x509.CertPool, domain string) *Handler {
	return &Handler{db: db, ca: caPool, domain: domain, store: newSessionStore()}
}

// HandleOMADM is the main OMA-DM endpoint. Devices POST here on every check-in.
//
// Flow:
//  1. Authenticate the device via its mTLS client certificate
//  2. Parse the SyncML body
//  3. Process Status and Results from the device
//  4. Build a response: ACKs + pending commands from the queue
//  5. Return the SyncML response
//
// POST /omadm
func (h *Handler) HandleOMADM(w http.ResponseWriter, r *http.Request) {
	// ── Step 1: Authenticate device by client certificate ─────────────────
	deviceID, err := h.authenticateDevice(r)
	if err != nil {
		slog.Warn("mdm: device authentication failed", "remote", r.RemoteAddr, "err", err)
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}

	// ── Step 2: Parse SyncML body ─────────────────────────────────────────
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB limit
	if err != nil {
		slog.Error("mdm: reading request body", "device_id", deviceID, "err", err)
		http.Error(w, "error reading body", http.StatusBadRequest)
		return
	}

	var incoming SyncML
	if err := xml.Unmarshal(body, &incoming); err != nil {
		slog.Error("mdm: parsing SyncML", "device_id", deviceID, "err", err)
		http.Error(w, "invalid SyncML", http.StatusBadRequest)
		return
	}

	msgID := incoming.SyncHdr.MsgID
	sessionID := incoming.SyncHdr.SessionID
	deviceURI := incoming.SyncHdr.Source.LocURI

	// Detect first session (alert 1200 = bootstrap after enrollment)
	isFirst := false
	for _, alert := range incoming.SyncBody.Alerts {
		if alert.Data == AlertCodeFirstSession {
			isFirst = true
		}
	}

	// Get or create the session, and serialize all processing for it. A single
	// OMA-DM session may be driven by concurrent connections; holding the session
	// lock prevents concurrent mutation of CmdMap / the ID counters (which would
	// otherwise crash the whole process on a detected concurrent map write).
	sess := h.store.get(deviceID, sessionID, isFirst)
	sess.mu.Lock()
	defer sess.mu.Unlock()

	slog.Info("mdm: check-in received",
		"device_id", deviceID,
		"session_id", sessionID,
		"msg_id", msgID,
		"first_session", isFirst,
		"alerts", len(incoming.SyncBody.Alerts),
		"statuses", len(incoming.SyncBody.Statuses),
		"results", len(incoming.SyncBody.Results),
	)

	// ── Step 3: Update checkin timestamp and status ──────────────────────
	// ── Step 3: Update checkin timestamp and status ──────────────────────
	if _, err := h.db.Exec(
		`UPDATE devices SET last_checkin = ?, compliance_status = 'compliant' WHERE id = ?`,
		time.Now().UTC(), deviceID,
	); err != nil {
		slog.Error("mdm: failed to update device status", "device_id", deviceID, "err", err)
	}

	// ── Step 4: Process Status responses (command result ACKs) ────────────
	h.processStatuses(deviceID, sess, incoming.SyncBody.Statuses)

	// ── Step 5: Process Results (device values, responds to our Gets) ─────
	updateDeviceFromResults(h.db, deviceID, sess, incoming.SyncBody.Results)

	// ── Step 6: Build commands to deliver ─────────────────────────────────
	var outboundCmds []interface{}

	// Check if we already have device info (interrogate if missing OS version or Build)
	var osVersion, osBuild sql.NullString
	_ = h.db.QueryRow(dbpkg.Rebind(`SELECT os_version, os_build FROM devices WHERE id = ?`), deviceID).Scan(&osVersion, &osBuild)

	if isFirst || !osVersion.Valid || osVersion.String == "" || !osBuild.Valid || osBuild.String == "" {
		// On the first session, or until we have full info, interrogation it
		slog.Info("mdm: device info incomplete — interrogating", "device_id", deviceID)
		outboundCmds = append(outboundCmds, buildFirstCheckInCommands(sess)...)
	}

	// Load any pending commands from the queue
	pending, err := loadPendingCommands(h.db, deviceID)
	if err != nil {
		slog.Error("mdm: loading pending commands", "device_id", deviceID, "err", err)
	} else {
		outboundCmds = append(outboundCmds, buildSyncMLCommands(sess, pending)...)
		// Mark as sent
		ids := make([]int, len(pending))
		for i, c := range pending {
			ids[i] = c.ID
		}
		if err := markCommandsSent(h.db, ids); err != nil {
			slog.Error("mdm: marking commands sent", "device_id", deviceID, "err", err)
		}
	}

	// ── Step 7: Build SyncML response ────────────────────────────────────
	serverMsgID := strconv.Itoa(sess.NextMsgID)
	sess.NextMsgID++

	serverURI := "https://" + h.domain + "/omadm"

	// Build status ACKs for what the device sent us
	var statuses []Status

	// Always ACK the SyncHdr
	statuses = append(statuses, Status{
		MsgRef:    msgID,
		CmdRef:    "0",
		CmdID:     "1",
		Cmd:       "SyncHdr",
		TargetRef: serverURI,
		SourceRef: deviceURI,
		Data:      StatusOK,
	})

	// ACK each Alert
	for _, alert := range incoming.SyncBody.Alerts {
		statuses = append(statuses, Status{
			MsgRef: msgID,
			CmdRef: alert.CmdID,
			CmdID:  sess.nextCmdID(),
			Cmd:    "Alert",
			Data:   StatusOK,
		})
	}

	// ACK each Get (if device sent Get commands, which is unusual but valid)
	for _, get := range incoming.SyncBody.Gets {
		statuses = append(statuses, Status{
			MsgRef: msgID,
			CmdRef: get.CmdID,
			CmdID:  sess.nextCmdID(),
			Cmd:    "Get",
			Data:   StatusOK,
		})
	}

	// Write the response XML manually to preserve ordering (statuses before commands)
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	buf.WriteString(`<SyncML xmlns="SYNCML:SYNCML1.2">`)

	// Header
	hdr := SyncHdr{
		VerDTD:    syncMLDTD,
		VerProto:  syncMLProto,
		SessionID: sessionID,
		MsgID:     serverMsgID,
		Target:    LocURI{LocURI: deviceURI},
		Source:    LocURI{LocURI: serverURI},
	}
	hdrXML, _ := xml.Marshal(hdr)
	buf.WriteString("<SyncHdr>")
	// Inline the header fields (xml.Marshal wraps in element name)
	buf.WriteString(xmlInner(hdrXML, "SyncHdr"))
	buf.WriteString("</SyncHdr>")

	buf.WriteString("<SyncBody>")

	// Statuses
	for _, s := range statuses {
		sXML, _ := xml.Marshal(s)
		buf.Write(sXML)
	}

	// Commands
	for _, cmd := range outboundCmds {
		cXML, _ := xml.Marshal(cmd)
		buf.Write(cXML)
	}

	buf.WriteString("<Final/>")
	buf.WriteString("</SyncBody>")
	buf.WriteString("</SyncML>")

	slog.Info("mdm: responding to check-in",
		"device_id", deviceID,
		"commands_sent", len(outboundCmds),
		"response_size", buf.Len(),
	)

	w.Header().Set("Content-Type", "application/vnd.syncml.dm+xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())

	// If we had no commands, session is done
	if len(outboundCmds) == 0 {
		h.store.remove(deviceID, sessionID)
	}
}

// ── Device authentication ─────────────────────────────────────────────────────

// authenticateDevice verifies the device's mTLS client certificate against our CA.
// Returns the device ID from the database.
func (h *Handler) authenticateDevice(r *http.Request) (string, error) {
	// Get peer certificates from TLS
	var peerCerts []*x509.Certificate
	if r.TLS != nil {
		peerCerts = r.TLS.PeerCertificates
	}

	if len(peerCerts) == 0 {
		// If no cert presented (or behind a reverse proxy like Cloud Run),
		// try to identify by source URI from body (Hardware ID).
		return h.lookupDeviceByRequest(r)
	}

	// Verify the cert chain against our CA
	if h.ca != nil {
		opts := x509.VerifyOptions{
			Roots:     h.ca,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if _, err := peerCerts[0].Verify(opts); err != nil {
			return "", errorf("certificate verification failed: %v", err)
		}
	}

	// Look up device by certificate thumbprint
	thumbprint := certThumbprint(peerCerts[0])
	var deviceID string
	err := h.db.QueryRow(dbpkg.Rebind(`
		SELECT device_id FROM certificates
		WHERE thumbprint = ? AND cert_type = 'device' AND revoked = 0
	`), thumbprint).Scan(&deviceID)

	if err == sql.ErrNoRows {
		return "", errorf("no device found for certificate thumbprint %s", thumbprint)
	}
	if err != nil {
		return "", errorf("database error looking up device: %v", err)
	}

	return deviceID, nil
}

// lookupDeviceByRequest finds a device from the SyncML body source URI.
// Used in development when mTLS is not configured end-to-end.
func (h *Handler) lookupDeviceByRequest(r *http.Request) (string, error) {
	// 1. Try to get HWID from query parameter (for Cloud Run no-mTLS fallback)
	if hwid := r.URL.Query().Get("hwid"); hwid != "" {
		var deviceID string
		err := h.db.QueryRow(
			dbpkg.Rebind(`SELECT id FROM devices WHERE hardware_id = ? AND is_active = 1`), hwid,
		).Scan(&deviceID)
		if err == nil {
			slog.Warn("mdm: device auth via query param hwid (no mTLS)", "device_id", deviceID, "hwid", hwid)
			return deviceID, nil
		}
	}

	// 2. Peek at the body to get the Source/LocURI
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	r.Body = io.NopCloser(bytes.NewReader(body)) // restore

	var msg SyncML
	if err := xml.Unmarshal(body, &msg); err != nil {
		return "", errorf("no client cert and SyncML parse failed")
	}

	hardwareID := msg.SyncHdr.Source.LocURI
	if hardwareID == "" {
		return "", errorf("no client cert and no source URI in SyncML")
	}

	var deviceID string
	err := h.db.QueryRow(
		dbpkg.Rebind(`SELECT id FROM devices WHERE hardware_id = ? AND is_active = 1`), hardwareID,
	).Scan(&deviceID)
	if err == sql.ErrNoRows {
		return "", errorf("device not found for hardware_id %s (not enrolled?)", hardwareID)
	}
	if err != nil {
		return "", errorf("database error: %v", err)
	}

	slog.Warn("mdm: device auth via hardware ID (no mTLS) — only acceptable in dev mode",
		"device_id", deviceID, "hardware_id", hardwareID,
	)
	return deviceID, nil
}

// ── Status processing ─────────────────────────────────────────────────────────

// processStatuses handles the Status elements the device sends us.
// These are the device's responses to commands we sent in a previous message.
func (h *Handler) processStatuses(deviceID string, sess *Session, statuses []Status) {
	for _, s := range statuses {
		if s.Cmd == "SyncHdr" {
			continue // Just an ACK of our header, nothing to action
		}

		slog.Info("mdm: command status received",
			"device_id", deviceID,
			"cmd", s.Cmd,
			"cmd_ref", s.CmdRef,
			"status", s.Data,
		)

		// Map CmdRef back to our command queue ID
		queueID, ok := sess.CmdMap[s.CmdRef]
		if !ok {
			// This might be a status for a command delivered in a previous TCP connection
			// but same OMA-DM session.
			continue
		}

		// Update command status in DB
		if err := markCommandResult(h.db, queueID, s.Data, ""); err != nil {
			slog.Error("mdm: failed to mark command result", "queue_id", queueID, "err", err)
		}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func certThumbprint(cert *x509.Certificate) string {
	h := sha1.Sum(cert.Raw)
	return fmt.Sprintf("%x", h[:])
}

func errorf(format string, args ...interface{}) error {
	return fmt.Errorf(format, args...)
}

// xmlInner extracts the inner XML between the opening and closing tags of element.
func xmlInner(data []byte, element string) string {
	open := []byte("<" + element + ">")
	closer := []byte("</" + element + ">")
	start := bytes.Index(data, open)
	end := bytes.LastIndex(data, closer)
	if start < 0 || end < 0 {
		return ""
	}
	return string(data[start+len(open) : end])
}
