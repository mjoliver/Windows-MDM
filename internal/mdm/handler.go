package mdm

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/devauth"
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

	pollMu              sync.Mutex
	pollConfigured      bool
	pollIntervalMinutes int
	pollOnLogin         bool
	pollSynced          map[string]string
	postureSynced       map[string]bool
	wnsPFN              string
	wnsPFNSynced        map[string]string
}

// NewHandler creates an OMA-DM handler. proxyCertHeader is "" unless a trusted
// proxy is configured to forward the device client certificate.
func NewHandler(db *sql.DB, caPool *x509.CertPool, domain, proxyCertHeader string) *Handler {
	return &Handler{
		db:              db,
		ca:              caPool,
		domain:          domain,
		store:           newSessionStore(),
		proxyCertHeader: proxyCertHeader,
		pollSynced:      make(map[string]string),
		postureSynced:   make(map[string]bool),
		wnsPFNSynced:    make(map[string]string),
	}
}

// SetPollSchedule configures periodic background check-in settings pushed to
// enrolled devices via the DMClient Poll CSP once per server lifecycle (or
// whenever the configured schedule changes).
func (h *Handler) SetPollSchedule(intervalMinutes int, pollOnLogin bool) {
	h.pollMu.Lock()
	defer h.pollMu.Unlock()
	if intervalMinutes < 0 {
		intervalMinutes = 0
	}
	sig := fmt.Sprintf("%d:%t", intervalMinutes, pollOnLogin)
	prev := fmt.Sprintf("%d:%t", h.pollIntervalMinutes, h.pollOnLogin)
	if !h.pollConfigured || sig != prev {
		h.pollSynced = make(map[string]string)
	}
	h.pollConfigured = true
	h.pollIntervalMinutes = intervalMinutes
	h.pollOnLogin = pollOnLogin
}

// SetWNSPFN configures the Microsoft Partner Center Package Family Name pushed
// to enrolled devices via DMClient/Provider/LatchzMDM/Push/PFN and triggers
// Push/ChannelURI interrogation when no active WNS channel is stored.
func (h *Handler) SetWNSPFN(pfn string) {
	h.pollMu.Lock()
	defer h.pollMu.Unlock()
	pfn = strings.TrimSpace(pfn)
	if pfn != h.wnsPFN {
		h.wnsPFNSynced = make(map[string]string)
	}
	h.wnsPFN = pfn
}

// reconcileWNSPush provisions DMClient Push/PFN once per server lifecycle and
// requests Push/ChannelURI + Push/Status whenever a device lacks a stored channel.
func (h *Handler) reconcileWNSPush(deviceID string, sess *Session) []interface{} {
	h.pollMu.Lock()
	pfn := h.wnsPFN
	if pfn == "" {
		h.pollMu.Unlock()
		return nil
	}
	needPFN := h.wnsPFNSynced[deviceID] != pfn
	if needPFN {
		h.wnsPFNSynced[deviceID] = pfn
	}
	h.pollMu.Unlock()

	var cmds []interface{}
	if needPFN {
		cmds = append(cmds, Replace{
			CmdID: sess.nextCmdID(),
			Items: []Item{{
				Target: &LocURI{LocURI: OMADMClientPushPFN},
				Meta: &Meta{
					Format: &MetaFormat{Xmlns: metInfNS, Value: "chr"},
					Type:   "text/plain",
				},
				Data: pfn,
			}},
		})
	}

	if !sess.WNSChannelQueried {
		needChannel := needPFN
		if !needChannel {
			var count int
			if err := h.db.QueryRow(
				dbpkg.Rebind(`SELECT COUNT(*) FROM device_wns_channels WHERE device_id = ?`),
				deviceID,
			).Scan(&count); err == nil && count == 0 {
				needChannel = true
			}
		}
		if needChannel {
			sess.WNSChannelQueried = true
			cmds = append(cmds,
				Get{CmdID: sess.nextCmdID(), Items: []Item{{Target: &LocURI{LocURI: OMADMClientPushChannelURI}}}},
				Get{CmdID: sess.nextCmdID(), Items: []Item{{Target: &LocURI{LocURI: OMADMClientPushStatus}}}},
			)
		}
	}

	return cmds
}

// reconcilePollSchedule returns DMClient Poll CSP Replace commands if this
// device has not yet received the active poll schedule during this server run.
func (h *Handler) reconcilePollSchedule(deviceID string, sess *Session) []interface{} {
	h.pollMu.Lock()
	if !h.pollConfigured {
		h.pollMu.Unlock()
		return nil
	}
	interval := h.pollIntervalMinutes
	onLogin := h.pollOnLogin
	sig := fmt.Sprintf("%d:%t", interval, onLogin)
	if h.pollSynced[deviceID] == sig {
		h.pollMu.Unlock()
		return nil
	}
	h.pollSynced[deviceID] = sig
	h.pollMu.Unlock()

	mkReplace := func(uri, data, format string) Replace {
		return Replace{
			CmdID: sess.nextCmdID(),
			Items: []Item{{
				Target: &LocURI{LocURI: uri},
				Meta: &Meta{
					Format: &MetaFormat{Xmlns: metInfNS, Value: format},
					Type:   "text/plain",
				},
				Data: data,
			}},
		}
	}

	return []interface{}{
		mkReplace(OMADMClientPollNumRemaining, "0", "int"),
		mkReplace(OMADMClientPollFrequency, strconv.Itoa(interval), "int"),
		mkReplace(OMADMClientPollOnLogin, strconv.FormatBool(onLogin), "bool"),
	}
}

// reconcileInitialPosture queries hardware & security posture once per server
// lifecycle for already-enrolled devices that have no device_posture record yet.
func (h *Handler) reconcileInitialPosture(deviceID string, sess *Session) []interface{} {
	h.pollMu.Lock()
	if h.postureSynced[deviceID] {
		h.pollMu.Unlock()
		return nil
	}
	h.pollMu.Unlock()

	var count int
	if err := h.db.QueryRow(
		dbpkg.Rebind(`SELECT COUNT(*) FROM device_posture WHERE device_id = ?`),
		deviceID,
	).Scan(&count); err != nil || count > 0 {
		h.pollMu.Lock()
		h.postureSynced[deviceID] = true
		h.pollMu.Unlock()
		return nil
	}

	h.pollMu.Lock()
	if h.postureSynced[deviceID] {
		h.pollMu.Unlock()
		return nil
	}
	h.postureSynced[deviceID] = true
	h.pollMu.Unlock()

	return buildFirstCheckInCommands(sess)
}

// reconcileActiveAppPolls issues Status/LastError/LastErrorDesc Get commands once
// per OMA-DM session for any MSI deployment on this device that has not yet
// reached a terminal state (30=Download Failed, 60=Install Failed, 70=Installed).
func (h *Handler) reconcileActiveAppPolls(deviceID string, sess *Session, alreadySent []PendingCommand) []interface{} {
	if sess.AppStatusQueried {
		return nil
	}

	sentURIs := make(map[string]bool, len(alreadySent))
	for _, c := range alreadySent {
		if c.CommandType == "Get" {
			sentURIs[c.OMAURI] = true
		}
	}

	rows, err := h.db.Query(dbpkg.Rebind(`
		SELECT product_code
		FROM device_app_installs
		WHERE device_id = ?
		  AND desired_action = 'install'
		  AND COALESCE(status_code, -1) NOT IN (30, 60, 70)
	`), deviceID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var prodCodes []string
	for rows.Next() {
		var code string
		if rows.Scan(&code) == nil && code != "" {
			prodCodes = append(prodCodes, code)
		}
	}
	if len(prodCodes) == 0 {
		return nil
	}

	sess.AppStatusQueried = true
	var cmds []interface{}
	for _, code := range prodCodes {
		for _, leaf := range []string{"Status", "LastError", "LastErrorDesc"} {
			uri := EncodeMSIProductURI(code, leaf)
			if sentURIs[uri] {
				continue
			}
			cmds = append(cmds, Get{
				CmdID: sess.nextCmdID(),
				Items: []Item{{Target: &LocURI{LocURI: uri}}},
			})
		}
	}
	return cmds
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
	interrogatedThisTurn := false
	if (isFirst || infoIncomplete) && sess.Interrogations < maxInterrogations {
		// On the first session, or until we have full info, interrogate the device.
		// Bounded so a device that never reports complete info isn't re-queried forever.
		slog.Info("mdm: device info incomplete — interrogating", "device_id", deviceID, "round", sess.Interrogations+1)
		outboundCmds = append(outboundCmds, buildFirstCheckInCommands(sess)...)
		sess.Interrogations++
		interrogatedThisTurn = true
		h.pollMu.Lock()
		h.postureSynced[deviceID] = true
		h.pollMu.Unlock()
	}

	// Load any pending commands from the queue
	wipeDelivered := false
	pending, err := loadPendingCommands(h.db, deviceID)
	if err != nil {
		slog.Error("mdm: loading pending commands", "device_id", deviceID, "err", err)
	} else {
		outboundCmds = append(outboundCmds, buildSyncMLCommands(sess, pending)...)
		// Mark as sent
		ids := make([]int, len(pending))
		for i, c := range pending {
			ids[i] = c.ID
			if c.CommandType == "Exec" && c.OMAURI == OMAExecWipe {
				wipeDelivered = true
			}
		}
		if err := markCommandsSent(h.db, ids); err != nil {
			slog.Error("mdm: marking commands sent", "device_id", deviceID, "err", err)
		}
		// Finalise teardown the moment the wipe is delivered: deactivate the
		// device and revoke its certificate. This is deliberate and fail-closed —
		// a wipe means "remove this device", and for a lost/compromised device we
		// want its access cut immediately rather than contingent on it cooperating
		// with (and ACKing) the wipe (a reset device rarely reports back anyway).
		// Tradeoff: if the wipe fails or is never received, the device must
		// re-enroll to be managed again (it cannot retry over the revoked cert).
		if wipeDelivered {
			h.finalizeWipe(deviceID)
		}
	}

	if !wipeDelivered {
		outboundCmds = append(outboundCmds, h.reconcilePollSchedule(deviceID, sess)...)
		if !interrogatedThisTurn {
			outboundCmds = append(outboundCmds, h.reconcileInitialPosture(deviceID, sess)...)
		}
		outboundCmds = append(outboundCmds, h.reconcileWNSPush(deviceID, sess)...)
		outboundCmds = append(outboundCmds, h.reconcileActiveAppPolls(deviceID, sess, pending)...)
	}

	// ── Step 7: Build SyncML response ────────────────────────────────────
	serverMsgID := strconv.Itoa(sess.NextMsgID)
	sess.NextMsgID++

	serverURI := "https://" + h.domain + "/omadm"
	if incoming.SyncHdr.Target.LocURI != "" {
		serverURI = incoming.SyncHdr.Target.LocURI
	}

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
// certificate (direct mTLS or a trusted-proxy-forwarded cert). There is NO
// hardware-ID fallback: a hardware_id is not a secret. Resolution rules live in
// the shared devauth package so the OMA-DM and WSTEP-renewal paths stay in sync.
func (h *Handler) authenticateDevice(r *http.Request) (string, error) {
	id, err := devauth.Resolve(h.db, h.ca, r, h.proxyCertHeader)
	if err != nil {
		return "", err
	}
	return id.DeviceID, nil
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

		// Look up command metadata so MSI Delete / Exec statuses also update device_app_installs
		var cmdType, cmdURI string
		_ = h.db.QueryRow(dbpkg.Rebind(`SELECT command_type, oma_uri FROM command_queue WHERE id = ?`), queueID).Scan(&cmdType, &cmdURI)

		resultCodeForQueue := s.Data
		if cmdType == "Delete" && s.Data == StatusNotFound {
			resultCodeForQueue = StatusOK
		}
		if prodCode, leaf, isMSI := ParseMSIProductURI(cmdURI); isMSI {
			if cmdType == "Delete" && leaf == "" && (s.Data == StatusOK || s.Data == StatusNoContent || s.Data == StatusNotFound) {
				resultCodeForQueue = StatusOK
				_, _ = h.db.Exec(dbpkg.Rebind(`
					UPDATE device_app_installs
					SET status_code = 0,
					    status_label = 'Uninstalled',
					    last_error = '',
					    last_error_desc = '',
					    updated_at = CURRENT_TIMESTAMP
					WHERE device_id = ? AND product_code = ?
				`), deviceID, prodCode)
			} else if cmdType == "Exec" && strings.EqualFold(leaf, "DownloadInstall") &&
				s.Data != StatusOK && s.Data != StatusCreated && s.Data != StatusAccepted && s.Data != StatusNoContent {
				_, _ = h.db.Exec(dbpkg.Rebind(`
					UPDATE device_app_installs
					SET status_code = 60,
					    status_label = 'Install Failed',
					    last_error = ?,
					    last_error_desc = 'SyncML Exec rejected by device',
					    updated_at = CURRENT_TIMESTAMP
					WHERE device_id = ? AND product_code = ?
				`), s.Data, deviceID, prodCode)
			}
		}

		// Update command status in DB
		if err := markCommandResult(h.db, queueID, resultCodeForQueue, ""); err != nil {
			slog.Error("mdm: failed to mark command result", "queue_id", queueID, "err", err)
		}
	}
}

// finalizeWipe deactivates the device and revokes its certificates after a
// remote-wipe command has been delivered. The device will factory-reset and
// lose its enrollment, so it must not remain a trusted, active device.
func (h *Handler) finalizeWipe(deviceID string) {
	if _, err := h.db.Exec(dbpkg.Rebind(`UPDATE devices SET is_active = 0 WHERE id = ?`), deviceID); err != nil {
		slog.Error("mdm: deactivating wiped device", "device_id", deviceID, "err", err)
	}
	if _, err := h.db.Exec(dbpkg.Rebind(`UPDATE certificates SET revoked = 1 WHERE device_id = ?`), deviceID); err != nil {
		slog.Error("mdm: revoking wiped device certs", "device_id", deviceID, "err", err)
	}
	_, _ = h.db.Exec(dbpkg.Rebind(`DELETE FROM device_wns_channels WHERE device_id = ?`), deviceID)
	slog.Info("mdm: remote wipe delivered — device deactivated and certs revoked", "device_id", deviceID)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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
