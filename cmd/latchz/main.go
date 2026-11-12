// Pane — open-source Windows MDM server.
// Round up your devices.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/google/subcommands"
	"github.com/google/uuid"
	"github.com/latchzmdm/latchz/internal/auth"
	"github.com/latchzmdm/latchz/internal/config"
	"github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/pki"
	"github.com/latchzmdm/latchz/internal/server"
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(&serveCmd{}, "")
	subcommands.Register(&adminCmd{}, "admin")
	subcommands.Register(&versionCmd{}, "")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}

// ── serve ─────────────────────────────────────────────────────────────────────

type serveCmd struct {
	configFile string
}

func (*serveCmd) Name() string     { return "serve" }
func (*serveCmd) Synopsis() string { return "Start the Latchz MDM server." }
func (*serveCmd) Usage() string {
	return `serve [-config <file>]:
  Start the Latchz MDM server. Enrollment, OMA-DM, and the admin dashboard
  all run on a single HTTPS port.

  Configuration is loaded from latchz.yaml, environment variables (LATCHZ_*),
  or the path specified with -config.

  Examples:
    latchz serve
    latchz serve -config /etc/latchz/latchz.yaml
    LATCHZ_DATABASE_DSN=postgres://... latchz serve

`
}

func (s *serveCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&s.configFile, "config", "", "Path to config file (default: latchz.yaml)")
}

func (s *serveCmd) Execute(ctx context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	cfg, err := config.Load(s.configFile)
	if err != nil {
		// config.Load validates required security settings (master secret,
		// auth provider, allowed domains) and fails closed on misconfiguration.
		fmt.Fprintf(os.Stderr, "latchz: configuration error: %v\n", err)
		return subcommands.ExitFailure
	}

	database, err := db.Open(cfg.Database.Driver, cfg.Database.DSN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "latchz: database error: %v\n", err)
		return subcommands.ExitFailure
	}
	defer database.Close()

	ca, err := pki.Load(database.DB, cfg.Server.MasterSecret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "latchz: PKI error: %v\n", err)
		return subcommands.ExitFailure
	}

	srv, err := server.New(cfg, database, ca)
	if err != nil {
		fmt.Fprintf(os.Stderr, "latchz: server setup error: %v\n", err)
		return subcommands.ExitFailure
	}

	if err := srv.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "latchz: %v\n", err)
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}

// ── admin ─────────────────────────────────────────────────────────────────────

type adminCmd struct {
	configFile string
	email      string
	role       string
	password   string
}

func (*adminCmd) Name() string     { return "admin" }
func (*adminCmd) Synopsis() string { return "Administrative operations (promote users, reset)." }
func (*adminCmd) Usage() string {
	return `admin -email <email> [-role <role>] [-password <pw>] [-config <file>]:
  Promote a user to admin directly in the database. Use this to recover
  from a lockout when normal login is unavailable.

  Examples:
    latchz admin -email matt@mjo.gg
    latchz admin -email matt@mjo.gg -role super_admin -password "..."

`
}

func (a *adminCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&a.configFile, "config", "", "Path to config file")
	f.StringVar(&a.email, "email", "", "Email address to promote")
	f.StringVar(&a.role, "role", "super_admin", "Role to assign (super_admin, admin, user)")
	f.StringVar(&a.password, "password", "", "Set a builtin-auth password for this user")
}

func (a *adminCmd) Execute(ctx context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if a.email == "" {
		fmt.Fprintln(os.Stderr, "latchz admin: -email is required")
		return subcommands.ExitUsageError
	}
	switch a.role {
	case "super_admin", "admin", "user":
	default:
		fmt.Fprintf(os.Stderr, "latchz admin: invalid role %q (use super_admin, admin, or user)\n", a.role)
		return subcommands.ExitUsageError
	}

	cfg, err := config.Load(a.configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "latchz admin: config error: %v\n", err)
		return subcommands.ExitFailure
	}

	database, err := db.Open(cfg.Database.Driver, cfg.Database.DSN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "latchz admin: database error: %v\n", err)
		return subcommands.ExitFailure
	}
	defer database.Close()

	// Upsert: create the user if absent, then set their role. IDs are generated
	// in Go and placeholders are rebound so this works on both SQLite and
	// Postgres (the previous query used sqlite-only randomblob() + ? params).
	_, err = database.ExecContext(ctx, db.Rebind(`
		INSERT INTO users (id, email, role, auth_provider)
		VALUES (?, ?, ?, 'builtin')
		ON CONFLICT(email) DO UPDATE SET role = excluded.role
	`), uuid.New().String(), a.email, a.role)
	if err != nil {
		fmt.Fprintf(os.Stderr, "latchz admin: failed to update user: %v\n", err)
		return subcommands.ExitFailure
	}

	if a.password != "" {
		hash, herr := auth.HashPassword(a.password)
		if herr != nil {
			fmt.Fprintf(os.Stderr, "latchz admin: hashing password: %v\n", herr)
			return subcommands.ExitFailure
		}
		if _, err := database.ExecContext(ctx, db.Rebind(
			`UPDATE users SET password_hash = ?, auth_provider = 'builtin' WHERE email = ?`,
		), hash, a.email); err != nil {
			fmt.Fprintf(os.Stderr, "latchz admin: failed to set password: %v\n", err)
			return subcommands.ExitFailure
		}
		fmt.Printf("✓ password set for %s\n", a.email)
	}

	fmt.Printf("✓ %s has been assigned role %q\n", a.email, a.role)
	return subcommands.ExitSuccess
}

// ── version ───────────────────────────────────────────────────────────────────

// Version is set at build time via ldflags: -ldflags "-X main.Version=1.0.0"
var Version = "dev"

type versionCmd struct{}

func (*versionCmd) Name() string             { return "version" }
func (*versionCmd) Synopsis() string         { return "Print version information." }
func (*versionCmd) Usage() string            { return "version\n" }
func (*versionCmd) SetFlags(_ *flag.FlagSet) {}
func (*versionCmd) Execute(_ context.Context, _ *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	fmt.Printf("latchz %s\n", Version)
	return subcommands.ExitSuccess
}
