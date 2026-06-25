package testutil

import (
	"testing"

	"github.com/google/uuid"
	"github.com/latchzmdm/latchz/internal/db"
)

// SeedUser inserts a user and returns its email.
func SeedUser(t testing.TB, database *db.DB, email, role string) string {
	t.Helper()
	_, err := database.Exec(db.Rebind(`
		INSERT INTO users (id, email, display_name, role, auth_provider)
		VALUES (?, ?, ?, ?, 'oidc')
	`), uuid.New().String(), email, email, role)
	if err != nil {
		t.Fatalf("testutil: seeding user: %v", err)
	}
	return email
}

// SeedDevice inserts an active device and returns its generated id.
func SeedDevice(t testing.TB, database *db.DB, hardwareID string) string {
	t.Helper()
	id := uuid.New().String()
	_, err := database.Exec(db.Rebind(`
		INSERT INTO devices (id, hardware_id, device_name, enrolled_by, compliance_status, is_active)
		VALUES (?, ?, ?, 'seed@test', 'pending', 1)
	`), id, hardwareID, "device-"+hardwareID)
	if err != nil {
		t.Fatalf("testutil: seeding device: %v", err)
	}
	return id
}

// SeedCatalogEntry inserts a policy_catalog row and returns its id.
func SeedCatalogEntry(t testing.TB, database *db.DB, omaURI, dataType string) int {
	t.Helper()
	var id int
	err := database.QueryRow(db.Rebind(`
		INSERT INTO policy_catalog (oma_uri, display_name, data_type, source)
		VALUES (?, ?, ?, 'manual') RETURNING id
	`), omaURI, omaURI, dataType).Scan(&id)
	if err != nil {
		t.Fatalf("testutil: seeding catalog entry: %v", err)
	}
	return id
}

// SeedProfileWithSetting creates a profile carrying a single (catalogID,value)
// setting and returns the profile id.
func SeedProfileWithSetting(t testing.TB, database *db.DB, catalogID int, desiredValue string) string {
	t.Helper()
	pid := uuid.New().String()
	if _, err := database.Exec(db.Rebind(`INSERT INTO profiles (id, name) VALUES (?, ?)`), pid, "profile-"+pid); err != nil {
		t.Fatalf("testutil: seeding profile: %v", err)
	}
	if _, err := database.Exec(db.Rebind(`
		INSERT INTO profile_settings (profile_id, catalog_id, desired_value) VALUES (?, ?, ?)
	`), pid, catalogID, desiredValue); err != nil {
		t.Fatalf("testutil: seeding profile setting: %v", err)
	}
	return pid
}

// AssignProfile wires a device into a new group that carries the given profile,
// returning the group id. Mirrors the device→group→profile resolution path.
func AssignProfile(t testing.TB, database *db.DB, deviceID, profileID string) string {
	t.Helper()
	gid := uuid.New().String()
	if _, err := database.Exec(db.Rebind(`INSERT INTO device_groups (id, name) VALUES (?, ?)`), gid, "group-"+gid); err != nil {
		t.Fatalf("testutil: seeding group: %v", err)
	}
	if _, err := database.Exec(db.Rebind(`INSERT INTO device_group_members (device_id, group_id) VALUES (?, ?)`), deviceID, gid); err != nil {
		t.Fatalf("testutil: seeding group membership: %v", err)
	}
	if _, err := database.Exec(db.Rebind(`INSERT INTO group_profiles (group_id, profile_id) VALUES (?, ?)`), gid, profileID); err != nil {
		t.Fatalf("testutil: seeding group profile: %v", err)
	}
	return gid
}
