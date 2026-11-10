package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentityCleanupFailureReportsCommittedState(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "identity"), filepath.Join(dir, "config.json")}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldRemove := removeIdentityBackup
	removeIdentityBackup = func(string) error { return os.ErrPermission }
	t.Cleanup(func() { removeIdentityBackup = oldRemove })
	err := writeFilesAtomic([]fileWrite{
		{path: paths[0], data: []byte("validated-new-identity"), mode: 0o600},
		{path: paths[1], data: []byte(`{"agent_id":"test-agent","token":""}`), mode: 0o600},
	})
	var committed *IdentityCleanupError
	if !errors.As(err, &committed) || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("cleanup failure must report a committed transaction: %v", err)
	}
	for i, path := range paths {
		data, readErr := os.ReadFile(path)
		if readErr != nil || string(data) == "previous" || len(data) == 0 {
			t.Fatalf("committed file %d missing: %q, %v", i, data, readErr)
		}
		backups, globErr := filepath.Glob(path + ".bak-*")
		if globErr != nil || len(backups) != 1 {
			t.Fatalf("missing private backup: %v, %v", backups, globErr)
		}
		info, statErr := os.Stat(backups[0])
		if statErr != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("backup permissions: %v", statErr)
		}
		if !strings.Contains(err.Error(), backups[0]) {
			t.Fatalf("cleanup error omits retained path: %v", err)
		}
	}
}
