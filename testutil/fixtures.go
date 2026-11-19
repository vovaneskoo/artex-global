package testutil

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
)

// SQLDB is the subset of *sql.DB the fixture helpers need. Both *sql.DB and
// *db.DB (which embeds it) satisfy it.
type SQLDB interface {
	Query(query string, args ...any) (*sql.Rows, error)
	Exec(query string, args ...any) (sql.Result, error)
}

// PreserveTable snapshots every row of table and restores exactly that state
// via t.Cleanup: rows the test added are deleted, rows it deleted or modified
// come back byte-identical (JSON round-trip through the table's row type).
//
// Use it for SHARED fixture state tests mutate globally — llm_profiles (the
// active/is_default profile) and settings (KV rows like the concurrency limit
// or LLM-judge config) — so later tests in the same suite, in any order
// (go test -shuffle=on), start from the state earlier tests found.
//
// table must be a plain identifier in the current schema; it is interpolated
// into SQL (identifiers cannot be parameterized), hence the strict allow-list
// check.
func PreserveTable(t *testing.T, db SQLDB, table string) {
	t.Helper()
	if !identifierPattern.MatchString(table) {
		t.Fatalf("PreserveTable: %q is not a plain SQL identifier", table)
	}
	var rows []json.RawMessage
	res, err := db.Query(fmt.Sprintf(`SELECT row_to_json(r) FROM %s r`, table))
	if err != nil {
		t.Fatalf("PreserveTable(%s): snapshot: %v", table, err)
	}
	defer res.Close()
	for res.Next() {
		var raw json.RawMessage
		if err := res.Scan(&raw); err != nil {
			t.Fatalf("PreserveTable(%s): scan: %v", table, err)
		}
		rows = append(rows, raw)
	}
	if err := res.Err(); err != nil {
		t.Fatalf("PreserveTable(%s): snapshot rows: %v", table, err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(fmt.Sprintf(`DELETE FROM %s`, table)); err != nil {
			t.Errorf("PreserveTable(%s): restore delete: %v", table, err)
			return
		}
		if len(rows) == 0 {
			return
		}
		blob, err := json.Marshal(rows)
		if err != nil {
			t.Errorf("PreserveTable(%s): marshal snapshot: %v", table, err)
			return
		}
		if _, err := db.Exec(
			fmt.Sprintf(`INSERT INTO %s SELECT (r).* FROM jsonb_populate_recordset(NULL::%s, $1::jsonb) r`, table, table),
			string(blob),
		); err != nil {
			t.Errorf("PreserveTable(%s): restore insert: %v", table, err)
		}
	})
}
