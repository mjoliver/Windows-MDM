// Package db manages database connections and schema migrations.
package db

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"

	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/lib/pq"        // Postgres driver
	_ "modernc.org/sqlite"       // SQLite driver (CGo-free)
)

//go:embed migrations/sqlite/*.sql migrations/postgres/*.sql
var migrationsFS embed.FS

// DriverName tracks the database engine used at runtime (sqlite or postgres)
var DriverName string

// DB wraps the standard sql.DB with Latchz-specific helpers.
type DB struct {
	*sql.DB
}

// Open opens a database connection and automatically runs any pending migrations.
func Open(driver, dsn string) (*DB, error) {
	DriverName = driver
	var sqlDB *sql.DB
	var err error

	switch driver {
	case "sqlite":
		// modernc sqlite uses "sqlite" as the driver name
		sqlDB, err = sql.Open("sqlite", dsn)
		if err != nil {
			return nil, fmt.Errorf("opening sqlite db: %w", err)
		}
		// WAL mode and busy timeout are critical for SQLite concurrency
		_, _ = sqlDB.Exec("PRAGMA journal_mode=WAL")
		_, _ = sqlDB.Exec("PRAGMA busy_timeout=5000")
		_, _ = sqlDB.Exec("PRAGMA synchronous=NORMAL")

		// With WAL mode, we can allow more than 1 connection safely
		sqlDB.SetMaxOpenConns(10)
		sqlDB.SetMaxIdleConns(5)

	case "postgres":
		// postgres driver must be imported by the caller for production builds
		sqlDB, err = sql.Open("postgres", dsn)
		if err != nil {
			return nil, fmt.Errorf("opening postgres db: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported database driver: %q (use sqlite or postgres)", driver)
	}

	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}

	db := &DB{sqlDB}

	if err := db.migrate(driver, dsn); err != nil {
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return db, nil
}

// migrate applies any pending SQL migrations from the embedded migrations directory.
func (db *DB) migrate(driver, dsn string) error {
	sourceDriver, err := iofs.New(migrationsFS, "migrations/"+driver)
	if err != nil {
		return fmt.Errorf("loading migration files: %w", err)
	}

	var m *migrate.Migrate

	switch driver {
	case "sqlite":
		dbDriver, err := sqlite.WithInstance(db.DB, &sqlite.Config{})
		if err != nil {
			return fmt.Errorf("creating sqlite migrate driver: %w", err)
		}
		m, err = migrate.NewWithInstance("iofs", sourceDriver, "sqlite", dbDriver)
		if err != nil {
			return fmt.Errorf("creating migrator: %w", err)
		}
	case "postgres":
		dbDriver, err := postgres.WithInstance(db.DB, &postgres.Config{})
		if err != nil {
			return fmt.Errorf("creating postgres migrate driver: %w", err)
		}
		m, err = migrate.NewWithInstance("iofs", sourceDriver, "postgres", dbDriver)
		if err != nil {
			return fmt.Errorf("creating migrator: %w", err)
		}
	default:
		return fmt.Errorf("migrations not configured for driver: %s", driver)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("applying migrations: %w", err)
	}

	version, _, _ := m.Version()
	slog.Info("database migrations applied", "version", version, "driver", driver)

	return nil
}

// Rebind converts standard '?' placeholders to PostgreSQL '$1, $2...' placeholders
// if the active database driver is 'postgres'. Otherwise, it returns the query unmodified.
func Rebind(query string) string {
	if DriverName != "postgres" {
		return query
	}

	var buf strings.Builder
	buf.Grow(len(query))
	paramIdx := 1
	inQuotes := false
	var quoteChar rune

	runes := []rune(query)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch r {
		case '\'', '"', '`':
			if !inQuotes {
				inQuotes = true
				quoteChar = r
			} else if quoteChar == r {
				if i+1 < len(runes) && runes[i+1] == r {
					buf.WriteRune(r)
					buf.WriteRune(r)
					i++
					continue
				}
				inQuotes = false
			}
			buf.WriteRune(r)
		case '?':
			if inQuotes {
				buf.WriteRune(r)
			} else {
				buf.WriteString(fmt.Sprintf("$%d", paramIdx))
				paramIdx++
			}
		default:
			buf.WriteRune(r)
		}
	}
	return buf.String()
}
