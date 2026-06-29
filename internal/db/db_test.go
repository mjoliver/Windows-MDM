package db

import (
	"strings"
	"testing"
)

func TestRebind(t *testing.T) {
	prev := DriverName
	t.Cleanup(func() { DriverName = prev })

	DriverName = "sqlite"
	if got := Rebind("SELECT 1 WHERE a = ? AND b = ?"); got != "SELECT 1 WHERE a = ? AND b = ?" {
		t.Fatalf("sqlite passthrough changed query: %q", got)
	}

	DriverName = "postgres"
	cases := []struct{ in, want string }{
		{"a = ? AND b = ?", "a = $1 AND b = $2"},
		{"x = ?", "x = $1"},
		{"name = 'a?b' AND y = ?", "name = 'a?b' AND y = $1"},     // ? inside single quotes preserved
		{`note = "what?" AND z = ?`, `note = "what?" AND z = $1`}, // ? inside double quotes preserved
		{"no params here", "no params here"},
	}
	for _, c := range cases {
		if got := Rebind(c.in); got != c.want {
			t.Errorf("Rebind(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestWithSQLitePragmas(t *testing.T) {
	if got := withSQLitePragmas("/tmp/x.db"); !strings.Contains(got, "?_pragma=") || !strings.Contains(got, "foreign_keys(ON)") {
		t.Fatalf("missing pragmas / wrong separator: %q", got)
	}
	if got := withSQLitePragmas("/tmp/x.db?cache=shared"); !strings.Contains(got, "&_pragma=") {
		t.Fatalf("expected & separator when query already present: %q", got)
	}
}
