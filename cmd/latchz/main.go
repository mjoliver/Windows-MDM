// Pane — open-source Windows MDM server.
// Round up your devices.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/google/subcommands"
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

  Configuration is loaded from pane.yaml, environment variables (PANE_*),
  or the path specified with -config.

  Examples:
    pane serve
    pane serve -config /etc/pane/pane.yaml
    PANE_DATABASE_DSN=postgres://... pane serve

`
}

func (s *serveCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&s.configFile, "config", "", "Path to config file (default: pane.yaml)")
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
		fmt.Fprintf(os.Stderr, "pane: database error: %v\n", err)
		return subcommands.ExitFailure
	}
	defer database.Close()

	ca, err := pki.Load(database.DB, cfg.Server.MasterSecret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pane: PKI error: %v\n", err)
		return subcommands.ExitFailure
	}

	srv, err := server.New(cfg, database, ca)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pane: server setup error: %v\n", err)
		return subcommands.ExitFailure
	}

	if err := srv.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "pane: %v\n", err)
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}

// ── admin ─────────────────────────────────────────────────────────────────────

type adminCmd struct {
	configFile string
	email      string
	role       string
}

func (*adminCmd) Name() string     { return "admin" }
func (*adminCmd) Synopsis() string { return "Administrative operations (promote users, reset)." }
func (*adminCmd) Usage() string {
	return `admin -email <email> [-role <role>] [-config <file>]:
  Promote a user to admin directly in the database. Use this to recover
  from a lockout when normal login is unavailable.

  Examples:
    pane admin -email matt@mjo.gg
    pane admin -email matt@mjo.gg -role super_admin

`
}

func (a *adminCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&a.configFile, "config", "", "Path to config file")
	f.StringVar(&a.email, "email", "", "Email address to promote")
	f.StringVar(&a.role, "role", "super_admin", "Role to assign (super_admin, admin, user)")
}

func (a *adminCmd) Execute(ctx context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if a.email == "" {
		fmt.Fprintln(os.Stderr, "pane admin: -email is required")
		return subcommands.ExitUsageError
	}

	cfg, err := config.Load(a.configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pane admin: config error: %v\n", err)
		return subcommands.ExitFailure
	}

	database, err := db.Open(cfg.Database.Driver, cfg.Database.DSN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pane admin: database error: %v\n", err)
		return subcommands.ExitFailure
	}
	defer database.Close()

	// Upsert: create user if not exists, then set role
	_, err = database.ExecContext(ctx, `
		INSERT INTO users (id, email, role, auth_provider)
		VALUES (lower(hex(randomblob(16))), ?, ?, 'builtin')
		ON CONFLICT(email) DO UPDATE SET role = excluded.role
	`, a.email, a.role)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pane admin: failed to update user: %v\n", err)
		return subcommands.ExitFailure
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
	fmt.Printf("pane %s\n", Version)
	return subcommands.ExitSuccess
}
