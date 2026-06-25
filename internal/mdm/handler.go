package mdm

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
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

	// proxyCertHeader, when non-empty, names a request header carrying a
	// URL-encoded PEM client certificate forwarded by a trusted terminating
	// proxy (tls.mode=none). Empty means only direct mTLS is accepted.
	proxyCertHeader string
}

// NewHandler creates an OMA-DM handler. proxyCertHeader is "" unless a trusted
// proxy is configured to forward the device client certificate.
func NewHandler(db *sql.DB, caPool *x509.CertPool, domain, proxyCertHeader string) *Handler {
	return &Handler{db: db, ca: caPool, domain: domain, store: newSessionStore(), proxyCertHeader: proxyCertHeader}
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

	// ── Step 3: Update check-in timestamp ────────────────────────────────
	// Only the last_checkin is updated here. Compliance status is computed from
	// the device's actual reported values (see refreshDeviceCompliance) — a
	// check-in must NOT blanket-mark the device compliant. (Also: Rebind so the
	// query works on Postgres, not just SQLite.)
	if _, err := h.db.Exec(
		dbpkg.Rebind(`UPDATE devices SET last_checkin = ? WHERE id = ?`),
		time.Now().UTC(), deviceID,
	); err != nil {
		slog.Error("mdm: failed to update device check-in time", "device_id", deviceID, "err", err)
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

	infoIncomplete := !osVersion.Valid || osVersion.String == "" || !osBuild.Valid || osBuild.String == ""
	if (isFirst || infoIncomplete) && sess.Interrogations < maxInterrogations {
		// On the first session, or until we have full info, interrogate the device.
		// Bounded so a device that never reports complete info isn't re-queried forever.
		slog.Info("mdm: device info incomplete — interrogating", "device_id", deviceID, "round", sess.Interrogations+1)
		outboundCmds = append(outboundCmds, buildFirstCheckInCommands(sess)...)
		sess.Interrogations++
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

// authenticateDevice identifies the device strictly by a verified client
// certificate. The certificate must chain to our CA and map to a non-revoked
// device certificate. There is NO hardware-ID fallback: a hardware_id is not a
// secret, so trusting it would let anyone impersonate any enrolled device.
//
// The certificate comes from one of:
//   - direct mTLS: r.TLS.PeerCertificates (already chain-verified by the TLS
//     stack, which uses VerifyClientCertIfGiven with our CA pool), or
//   - a trusted terminating proxy that forwards it in proxyCertHeader.
func (h *Handler) authenticateDevice(r *http.Request) (string, error) {
	clientCert, err := h.clientCert(r)
	if err != nil {
		return "", err
	}

	// Re-verify the chain to our CA (defence in depth; mandatory for the proxy
	// header path where the TLS stack did not verify it for us).
	if h.ca == nil {
		return "", errorf("no CA configured for device authentication")
	}
	if _, err := clientCert.Verify(x509.VerifyOptions{
		Roots:     h.ca,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return "", errorf("client certificate does not chain to our CA: %v", err)
	}

	// Look up the device by certificate thumbprint; reject revoked certs.
	thumbprint := certThumbprint(clientCert)
	var deviceID string
	err = h.db.QueryRow(dbpkg.Rebind(`
		SELECT device_id FROM certificates
		WHERE thumbprint = ? AND cert_type = 'device' AND revoked = 0
	`), thumbprint).Scan(&deviceID)
	if err == sql.ErrNoRows {
		return "", errorf("no active device for certificate thumbprint %s (revoked or unknown)", thumbprint)
	}
	if err != nil {
		return "", errorf("database error looking up device: %v", err)
	}
	return deviceID, nil
}

// clientCert extracts the device client certificate from the TLS peer chain or,
// if a trusted proxy is configured, from the forwarded header.
func (h *Handler) clientCert(r *http.Request) (*x509.Certificate, error) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0], nil
	}
	if h.proxyCertHeader != "" {
		raw := r.Header.Get(h.proxyCertHeader)
		if raw == "" {
			return nil, errorf("client certificate required: trusted-proxy header %q is empty", h.proxyCertHeader)
		}
		return parseProxyClientCert(raw)
	}
	return nil, errorf("client certificate required")
}

// parseProxyClientCert decodes a client certificate forwarded by a terminating
// proxy. It accepts a raw PEM string or a URL-encoded PEM (e.g. nginx
// $ssl_client_escaped_cert). The raw form is tried first so that base64 '+'
// characters are not mangled by URL-decoding.
func parseProxyClientCert(raw string) (*x509.Certificate, error) {
	candidates := []string{raw}
	if decoded, err := url.QueryUnescape(raw); err == nil && decoded != raw {
		candidates = append(candidates, decoded)
	}
	for _, c := range candidates {
		block, _ := pem.Decode([]byte(c))
		if block == nil {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			return cert, nil
		}
	}
	return nil, errorf("trusted-proxy client cert header is not a valid certificate")
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

		// If a remote wipe succeeded, finalise the device teardown: mark it
		// inactive and revoke its certificate (the device factory-resets and
		// loses its enrollment, so it must not remain a trusted, active device).
		if isSuccessStatus(s.Data) {
			h.finalizeWipeIfApplicable(deviceID, queueID)
		}
	}
}

// finalizeWipeIfApplicable deactivates the device and revokes its certs once a
// queued remote-wipe command has been confirmed executed.
func (h *Handler) finalizeWipeIfApplicable(deviceID string, queueID int) {
	var omaURI string
	if err := h.db.QueryRow(dbpkg.Rebind(`SELECT oma_uri FROM command_queue WHERE id = ?`), queueID).Scan(&omaURI); err != nil {
		return
	}
	if omaURI != OMAExecWipe {
		return
	}
	if _, err := h.db.Exec(dbpkg.Rebind(`UPDATE devices SET is_active = 0 WHERE id = ?`), deviceID); err != nil {
		slog.Error("mdm: deactivating wiped device", "device_id", deviceID, "err", err)
	}
	if _, err := h.db.Exec(dbpkg.Rebind(`UPDATE certificates SET revoked = 1 WHERE device_id = ?`), deviceID); err != nil {
		slog.Error("mdm: revoking wiped device certs", "device_id", deviceID, "err", err)
	}
	slog.Info("mdm: remote wipe confirmed — device deactivated and certs revoked", "device_id", deviceID)
}

func isSuccessStatus(code string) bool {
	return code == StatusOK || code == StatusCreated || code == StatusAccepted
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
