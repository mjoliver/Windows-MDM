-- Local drag-and-drop MSI package hosting metadata
ALTER TABLE msi_apps ADD COLUMN storage_filename TEXT NOT NULL DEFAULT '';
ALTER TABLE msi_apps ADD COLUMN original_filename TEXT NOT NULL DEFAULT '';
