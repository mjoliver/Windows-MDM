package mdm

import (
	"database/sql"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

	"github.com/latchzmdm/latchz/internal/db"
)

// PendingCommand is a command loaded from the command_queue table.
type PendingCommand struct {
	ID          int
	CommandType string // "Get", "Replace", "Add", "Delete", "Exec"
	OMAURI      string
	Payload     string
}

// loadPendingCommands loads all pending commands for a device.
func loadPendingCommands(dbConn *sql.DB, deviceID string) ([]PendingCommand, error) {
	rows, err := dbConn.Query(db.Rebind(`
		SELECT id, command_type, oma_uri, COALESCE(payload, '')
		FROM command_queue
		WHERE device_id = ? AND status = 'pending'
		ORDER BY id ASC
		LIMIT 20
	`), deviceID)
	if err != nil {
		return nil, fmt.Errorf("querying command queue: %w", err)
	}
	defer rows.Close()

	var cmds []PendingCommand
	for rows.Next() {
		var c PendingCommand
		if err := rows.Scan(&c.ID, &c.CommandType, &c.OMAURI, &c.Payload); err != nil {
			return nil, fmt.Errorf("scanning command: %w", err)
		}
		cmds = append(cmds, c)
	}
	return cmds, rows.Err()
}

// markCommandsSent updates the status of the queued commands to 'sent'.
func markCommandsSent(dbConn *sql.DB, ids []int) error {
	if len(ids) == 0 {
		return nil
	}
	// Build parameterised IN clause
	query := "UPDATE command_queue SET status = 'sent', sent_at = CURRENT_TIMESTAMP WHERE id IN ("
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		if i > 0 {
			query += ","
		}
		query += "?"
		args[i] = id
	}
	query += ")"
	_, err := dbConn.Exec(db.Rebind(query), args...)
	return err
}

func markCommandResult(dbConn *sql.DB, queueID int, resultCode, resultData string) error {
	status := "success"
	if resultCode != StatusOK &&
		resultCode != StatusCreated &&
		resultCode != StatusAccepted &&
		resultCode != StatusNoContent &&
		resultCode != StatusAlreadyExists {
		status = "failed"
	}

	if resultData != "" {
		_, err := dbConn.Exec(db.Rebind(`
			UPDATE command_queue
			SET status = ?, result_code = ?, result_data = ?, completed_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`), status, resultCode, resultData, queueID)
		return err
	}

	_, err := dbConn.Exec(db.Rebind(`
		UPDATE command_queue
		SET status = ?, result_code = ?, completed_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`), status, resultCode, queueID)
	return err
}

// EnqueueGet adds a Get command for a device to the command queue.
func EnqueueGet(dbConn *sql.DB, deviceID, omaURI string) (int64, error) {
	return enqueue(dbConn, deviceID, "Get", formatDeviceURI(omaURI), "")
}

// EnqueueReplace adds a Replace (set value) command to the queue.
func EnqueueReplace(dbConn *sql.DB, deviceID, omaURI, value string) (int64, error) {
	return enqueue(dbConn, deviceID, "Replace", formatDeviceURI(omaURI), value)
}

// EnqueueExec adds an Exec (trigger action) command to the queue.
func EnqueueExec(dbConn *sql.DB, deviceID, omaURI, payload string) (int64, error) {
	return enqueue(dbConn, deviceID, "Exec", formatDeviceURI(omaURI), payload)
}

// EnqueueAdd adds an Add (create node) command to the queue.
func EnqueueAdd(dbConn *sql.DB, deviceID, omaURI, payload string) (int64, error) {
	return enqueue(dbConn, deviceID, "Add", formatDeviceURI(omaURI), payload)
}

// EnqueueDelete adds a Delete command, used to retract a previously-applied
// policy node from the device.
func EnqueueDelete(dbConn *sql.DB, deviceID, omaURI string) (int64, error) {
	return enqueue(dbConn, deviceID, "Delete", formatDeviceURI(omaURI), "")
}

// MSIInstallSpec describes a Win32 MSI deployment job for the
// EnterpriseDesktopAppManagement CSP.
type MSIInstallSpec struct {
	ProductCode          string
	Version              string
	ContentURL           string
	ContentURLs          []string
	SHA256               string
	CommandLine          string
	TimeoutMinutes       int
	RetryCount           int
	RetryIntervalMinutes int
}

type msiInstallJobXML struct {
	XMLName xml.Name      `xml:"MsiInstallJob"`
	ID      string        `xml:"id,attr"`
	Product msiProductXML `xml:"Product"`
}

type msiProductXML struct {
	Version     string            `xml:"Version,attr"`
	Download    msiDownloadXML    `xml:"Download"`
	Validation  *msiValidationXML `xml:"Validation,omitempty"`
	Enforcement msiEnforcementXML `xml:"Enforcement"`
}

type msiDownloadXML struct {
	ContentURLs []string `xml:"ContentURLList>ContentURL"`
}

type msiValidationXML struct {
	FileHash string `xml:"FileHash"`
}

type msiEnforcementXML struct {
	CommandLine   string `xml:"CommandLine"`
	TimeOut       int    `xml:"TimeOut"`
	RetryCount    int    `xml:"RetryCount"`
	RetryInterval int    `xml:"RetryInterval"`
}

// BuildMSIInstallJobXML serializes an <MsiInstallJob> XML payload conforming to
// Microsoft's EnterpriseDesktopAppManagement CSP specification.
func BuildMSIInstallJobXML(spec MSIInstallSpec) string {
	prodCode := CanonicalMSIProductCode(spec.ProductCode)
	version := strings.TrimSpace(spec.Version)
	if version == "" {
		version = "1.0.0"
	}
	cmdLine := strings.TrimSpace(spec.CommandLine)
	if cmdLine == "" {
		cmdLine = "/quiet /norestart"
	}
	timeout := spec.TimeoutMinutes
	if timeout <= 0 {
		timeout = 15
	}
	retries := spec.RetryCount
	if retries < 0 {
		retries = 3
	}
	retryInterval := spec.RetryIntervalMinutes
	if retryInterval <= 0 {
		retryInterval = 5
	}

	var urls []string
	seen := make(map[string]bool)
	for _, rawU := range append(append([]string(nil), spec.ContentURLs...), spec.ContentURL) {
		u := strings.TrimSpace(rawU)
		if u != "" && !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}

	job := msiInstallJobXML{
		ID: prodCode,
		Product: msiProductXML{
			Version: version,
			Download: msiDownloadXML{
				ContentURLs: urls,
			},
			Enforcement: msiEnforcementXML{
				CommandLine:   cmdLine,
				TimeOut:       timeout,
				RetryCount:    retries,
				RetryInterval: retryInterval,
			},
		},
	}
	if hash := strings.ToUpper(strings.TrimSpace(spec.SHA256)); hash != "" {
		job.Product.Validation = &msiValidationXML{FileHash: hash}
	}

	raw, err := xml.Marshal(job)
	if err != nil {
		return ""
	}
	return string(raw)
}

// EnqueueMSIStatusGets queues OMA-DM Get commands for Status, LastError, and
// LastErrorDesc of an MSI ProductCode on the target device.
func EnqueueMSIStatusGets(dbConn *sql.DB, deviceID, productCode string) (int, error) {
	leaves := []string{"Status", "LastError", "LastErrorDesc"}
	var queued int
	for _, leaf := range leaves {
		if _, err := EnqueueGet(dbConn, deviceID, EncodeMSIProductURI(productCode, leaf)); err != nil {
			return queued, err
		}
		queued++
	}
	return queued, nil
}

// EnqueueMSIInstall queues the EnterpriseDesktopAppManagement <Add>, <Exec>,
// and initial <Get> status commands in strict FIFO order.
func EnqueueMSIInstall(dbConn *sql.DB, deviceID string, spec MSIInstallSpec) (int, error) {
	installURI := EncodeMSIProductURI(spec.ProductCode, "DownloadInstall")
	rootURI := EncodeMSIProductURI(spec.ProductCode, "")

	// Clear any pending install/uninstall commands for this product so <Add> is
	// guaranteed to precede <Exec> in command_queue id ASC order.
	_, _ = dbConn.Exec(db.Rebind(`
		DELETE FROM command_queue
		WHERE device_id = ? AND status = 'pending' AND oma_uri IN (?, ?)
	`), deviceID, installURI, rootURI)

	if _, err := EnqueueAdd(dbConn, deviceID, installURI, ""); err != nil {
		return 0, err
	}
	if _, err := EnqueueExec(dbConn, deviceID, installURI, BuildMSIInstallJobXML(spec)); err != nil {
		return 1, err
	}
	gets, err := EnqueueMSIStatusGets(dbConn, deviceID, spec.ProductCode)
	return 2 + gets, err
}

// EnqueueMSIUninstall cancels any pending install for productCode and queues
// an EnterpriseDesktopAppManagement <Delete> command on the product node.
func EnqueueMSIUninstall(dbConn *sql.DB, deviceID, productCode string) (int64, error) {
	installURI := EncodeMSIProductURI(productCode, "DownloadInstall")
	rootURI := EncodeMSIProductURI(productCode, "")

	_, _ = dbConn.Exec(db.Rebind(`
		DELETE FROM command_queue
		WHERE device_id = ? AND status = 'pending' AND oma_uri = ?
	`), deviceID, installURI)

	return EnqueueDelete(dbConn, deviceID, rootURI)
}

// formatDeviceURI ensures that Policy CSP URIs have the required ./Device/ prefix
// before they are sent to the Windows client.
func formatDeviceURI(uri string) string {
	if strings.HasPrefix(uri, "./Vendor/MSFT/Policy/Config/") {
		return strings.Replace(uri, "./Vendor/", "./Device/Vendor/", 1)
	}
	return uri
}

// EnqueueLock queues a remote lock command.
func EnqueueLock(dbConn *sql.DB, deviceID string) (int64, error) {
	return EnqueueExec(dbConn, deviceID, OMAExecLock, "")
}

// EnqueueWipe queues a factory reset command. Destructive — use with caution.
func EnqueueWipe(dbConn *sql.DB, deviceID string) (int64, error) {
	return EnqueueExec(dbConn, deviceID, OMAExecWipe, "")
}

// EnqueueReboot queues a device reboot command.
func EnqueueReboot(dbConn *sql.DB, deviceID string) (int64, error) {
	return EnqueueExec(dbConn, deviceID, OMAExecReboot, "")
}

// EnqueuePostureRefresh queues OMA-DM Get commands for hardware inventory and
// Windows security posture nodes (Secure Boot, BitLocker, Defender, Firewall, TPM, RAM/Disk).
func EnqueuePostureRefresh(dbConn *sql.DB, deviceID string) (int, error) {
	var queued int
	for _, uri := range FirstCheckInURIs {
		if _, err := EnqueueGet(dbConn, deviceID, uri); err != nil {
			return queued, err
		}
		queued++
	}
	return queued, nil
}

func enqueue(dbConn *sql.DB, deviceID, commandType, omaURI, payload string) (int64, error) {
	// Dedup: if an equivalent command for this (device, uri, type) is already
	// pending, update its payload instead of piling up duplicates (repeated
	// Sync / profile re-apply would otherwise grow the queue without bound).
	var existingID int64
	err := dbConn.QueryRow(db.Rebind(`
		SELECT id FROM command_queue
		WHERE device_id = ? AND oma_uri = ? AND command_type = ? AND status = 'pending'
		LIMIT 1
	`), deviceID, omaURI, commandType).Scan(&existingID)
	switch {
	case err == nil:
		if _, uerr := dbConn.Exec(db.Rebind(`
			UPDATE command_queue SET payload = ?, created_at = CURRENT_TIMESTAMP WHERE id = ?
		`), nullableString(payload), existingID); uerr != nil {
			return 0, fmt.Errorf("updating pending command: %w", uerr)
		}
		return existingID, nil
	case errors.Is(err, sql.ErrNoRows):
		// no pending duplicate — insert below
	default:
		return 0, fmt.Errorf("checking pending command: %w", err)
	}

	var lastInsertID int64
	if err := dbConn.QueryRow(db.Rebind(`
		INSERT INTO command_queue (device_id, command_type, oma_uri, payload)
		VALUES (?, ?, ?, ?)
		RETURNING id
	`), deviceID, commandType, omaURI, nullableString(payload)).Scan(&lastInsertID); err != nil {
		return 0, fmt.Errorf("enqueueing command: %w", err)
	}
	return lastInsertID, nil
}

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// buildSyncMLCommands converts pending DB commands into SyncML command structs.
func buildSyncMLCommands(session *Session, pending []PendingCommand) []interface{} {
	var commands []interface{}
	for _, cmd := range pending {
		cmdID := session.nextCmdID()
		session.CmdMap[cmdID] = cmd.ID
		item := Item{
			Target: &LocURI{LocURI: cmd.OMAURI},
		}
		if cmd.Payload != "" {
			item.Data = cmd.Payload
			if strings.HasPrefix(strings.TrimSpace(cmd.Payload), "<MsiInstallJob") {
				item.RawXML = true
				item.Meta = &Meta{
					Format: &MetaFormat{
						Xmlns: metInfNS,
						Value: "xml",
					},
				}
			} else {
				format := "chr"
				// Match OMA-DM MetInf format for numeric and boolean values
				if isNumeric(cmd.Payload) {
					format = "int"
				} else if isBoolean(cmd.Payload) {
					format = "bool"
				}

				item.Meta = &Meta{
					Format: &MetaFormat{
						Xmlns: metInfNS,
						Value: format,
					},
					Type: "text/plain",
				}
			}
		}

		switch cmd.CommandType {
		case "Get":
			commands = append(commands, Get{
				CmdID: cmdID,
				Items: []Item{item},
			})
		case "Replace":
			commands = append(commands, Replace{
				CmdID: cmdID,
				Items: []Item{item},
			})
		case "Add":
			commands = append(commands, Add{
				CmdID: cmdID,
				Items: []Item{item},
			})
		case "Delete":
			commands = append(commands, Delete{
				CmdID: cmdID,
				Items: []Item{item},
			})
		case "Exec":
			commands = append(commands, Exec{
				CmdID: cmdID,
				Items: []Item{item},
			})
		}
	}
	return commands
}

// buildFirstCheckInCommands returns the Get commands we issue on a device's
// very first OMA-DM session to populate the device record.
func buildFirstCheckInCommands(session *Session) []interface{} {
	var cmds []interface{}
	for _, uri := range FirstCheckInURIs {
		cmds = append(cmds, Get{
			CmdID: session.nextCmdID(),
			Items: []Item{{Target: &LocURI{LocURI: uri}}},
		})
	}
	return cmds
}
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isBoolean(s string) bool {
	return s == "true" || s == "false"
}
