package store

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
)

func TestStateReturnsDeepSnapshot(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithState(true, func(s *domain.State) error {
		s.Agents["a1"] = &domain.Agent{ID: "a1", Name: "original"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	snapshot := st.State()
	snapshot.Agents["a1"].Name = "changed"
	snapshot.Agents["a2"] = &domain.Agent{ID: "a2", RegisteredAt: time.Now()}

	current := st.State()
	if current.Agents["a1"].Name != "original" {
		t.Fatalf("snapshot mutated store: %q", current.Agents["a1"].Name)
	}
	if current.Agents["a2"] != nil {
		t.Fatal("snapshot map aliases store map")
	}
}

func TestWriteAgentDeployLogLastWriteWins(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WriteAgentDeployLog("cert1", "agent1", "first"); err != nil {
		t.Fatal(err)
	}
	if err := st.WriteAgentDeployLog("cert1", "agent1", "second"); err != nil {
		t.Fatal(err)
	}
	got, err := st.ReadAgentDeployLog("cert1", "agent1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "second" {
		t.Fatalf("log = %q, want second", got)
	}
	empty, err := st.ReadAgentDeployLog("cert1", "missing")
	if err != nil {
		t.Fatal(err)
	}
	if empty != "" {
		t.Fatalf("missing log = %q, want empty", empty)
	}
}

func TestTransformSnapshotsValidatesBothBeforeWriting(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"backup", "primary"} {
		if err := st.WithState(true, func(s *domain.State) error { s.Admin.Username = name; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	primary, _ := os.ReadFile(st.StatePath())
	backup, _ := os.ReadFile(st.StatePath() + ".backup")
	err = st.TransformSnapshots(func(s *domain.State) (bool, error) {
		if s.Admin.Username == "backup" {
			return false, errors.New("reject backup")
		}
		s.Admin.Username = "changed"
		return true, nil
	})
	if err == nil {
		t.Fatal("backup validation failure ignored")
	}
	afterPrimary, _ := os.ReadFile(st.StatePath())
	afterBackup, _ := os.ReadFile(st.StatePath() + ".backup")
	if string(primary) != string(afterPrimary) || string(backup) != string(afterBackup) || st.State().Admin.Username != "primary" {
		t.Fatal("failed migration changed state")
	}
}

func TestTransformSnapshotsBackupWriteFailurePreservesPrimary(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := st.WithState(true, func(s *domain.State) error { s.Admin.Username = "original"; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	primary, _ := os.ReadFile(st.StatePath())
	if err := os.Mkdir(st.StatePath()+".backup.tmp", 0700); err != nil {
		t.Fatal(err)
	}
	err = st.TransformSnapshots(func(s *domain.State) (bool, error) { s.Admin.Username = "changed"; return true, nil })
	after, _ := os.ReadFile(st.StatePath())
	if err == nil || string(primary) != string(after) || st.State().Admin.Username != "original" {
		t.Fatal("backup failure did not abort primary migration")
	}
}

func TestWithStateCallbackErrorLeavesMemoryAndDiskUntouched(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *domain.State) error { s.Admin.Username = "before"; return nil }); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(st.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	if err := st.Update(func(s *domain.State) error {
		s.Admin.Username = "after"
		s.Agents["leak"] = &domain.Agent{ID: "leak"}
		return boom
	}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	if got := st.State().Admin.Username; got != "before" {
		t.Fatalf("memory username = %q, want before", got)
	}
	if st.State().Agents["leak"] != nil {
		t.Fatal("callback mutation leaked into memory")
	}
	after, err := os.ReadFile(st.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("callback error changed state.json")
	}
}

func TestWithStatePersistenceFailureKeepsMemoryAndDiskAndAllowsRetry(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *domain.State) error { s.Admin.Username = "before"; return nil }); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(st.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	// A directory at the temp path makes the write fail deterministically.
	if err := os.Mkdir(st.StatePath()+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	err = st.Update(func(s *domain.State) error { s.Admin.Username = "after"; return nil })
	if err == nil {
		t.Fatal("expected persistence failure")
	}
	if got := st.State().Admin.Username; got != "before" {
		t.Fatalf("memory username = %q, want before", got)
	}
	after, err := os.ReadFile(st.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("failed write changed state.json")
	}
	if err := os.Remove(st.StatePath() + ".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *domain.State) error { s.Admin.Username = "after"; return nil }); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if got := st.State().Admin.Username; got != "after" {
		t.Fatalf("retry username = %q, want after", got)
	}
	onDisk, err := os.ReadFile(st.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(onDisk), `"after"`) {
		t.Fatal("retry did not persist")
	}
}

func TestWithStateCommitFalseUpdatesMemoryWithoutWriting(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithState(false, func(s *domain.State) error {
		s.Admin.Username = "memory-only"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := st.State().Admin.Username; got != "memory-only" {
		t.Fatalf("username = %q", got)
	}
	if _, err := os.Stat(st.StatePath()); !os.IsNotExist(err) {
		t.Fatalf("commit=false wrote state file: %v", err)
	}
}

func TestSaveKeepsPreviousStateAsBackup(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *domain.State) error { s.Admin.Username = "first"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *domain.State) error { s.Admin.Username = "second"; return nil }); err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(st.StatePath() + ".backup")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(backup), `"first"`) {
		t.Fatalf("backup does not hold previous state: %s", backup)
	}
	primary, err := os.ReadFile(st.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(primary), `"second"`) {
		t.Fatalf("primary does not hold new state: %s", primary)
	}
}

func TestLoadRepairsCorruptPrimaryFromBackup(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *domain.State) error { s.Admin.Username = "first"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *domain.State) error { s.Admin.Username = "second"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(st.StatePath(), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := reopened.State().Admin.Username; got != "first" {
		t.Fatalf("recovered username = %q, want first", got)
	}
	repaired, err := os.ReadFile(reopened.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(repaired), `"first"`) {
		t.Fatal("corrupt primary was not repaired from backup")
	}
}

func TestConcurrentUpdatesAreSerialized(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const workers = 24
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := st.Update(func(s *domain.State) error {
				s.AdminLogins = append(s.AdminLogins, domain.AdminLogin{Username: "concurrent"})
				return nil
			}); err != nil {
				t.Errorf("update: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := len(st.State().AdminLogins); got != workers {
		t.Fatalf("logins = %d, want %d (lost update)", got, workers)
	}
}

func TestUpdateGuardsFirstAdminInitialization(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	errAlready := errors.New("already initialized")
	initialize := func(name string) error {
		return st.Update(func(s *domain.State) error {
			if s.Admin.SetupTokenUsed {
				return errAlready
			}
			s.Admin.Username = name
			s.Admin.SetupTokenUsed = true
			return nil
		})
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, name := range []string{"alice", "bob"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			results <- initialize(name)
		}(name)
	}
	wg.Wait()
	close(results)
	var succeeded, rejected int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, errAlready):
			rejected++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("succeeded=%d rejected=%d, want 1/1", succeeded, rejected)
	}
	if got := st.State().Admin.Username; got != "alice" && got != "bob" {
		t.Fatalf("unexpected username %q", got)
	}
}

func TestSaveBackupWriteFailureKeepsPrimaryAndMemory(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *domain.State) error { s.Admin.Username = "before"; return nil }); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(st.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(st.StatePath()+".backup.tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *domain.State) error { s.Admin.Username = "after"; return nil }); err == nil {
		t.Fatal("expected backup write failure")
	}
	if got := st.State().Admin.Username; got != "before" {
		t.Fatalf("memory username = %q", got)
	}
	after, err := os.ReadFile(st.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("backup failure changed primary")
	}
	if _, err := os.Stat(st.StatePath() + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("primary temp not cleaned: %v", err)
	}
	if fi, err := os.Stat(st.StatePath() + ".backup.tmp"); err != nil || !fi.IsDir() {
		t.Fatalf("test-injected backup temp directory was removed: %v", err)
	}
	if err := os.Remove(st.StatePath() + ".backup.tmp"); err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *domain.State) error { s.Admin.Username = "after"; return nil }); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if got := st.State().Admin.Username; got != "after" {
		t.Fatalf("retry username = %q", got)
	}
}

func TestSavePrimaryRenameFailureKeepsPrimaryAndMemory(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *domain.State) error { s.Admin.Username = "before"; return nil }); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(st.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	originalRename := renameStateFile
	renameStateFile = func(oldpath, newpath string) error {
		if newpath == st.StatePath() {
			return errors.New("injected primary rename failure")
		}
		return os.Rename(oldpath, newpath)
	}
	defer func() { renameStateFile = originalRename }()
	if err := st.Update(func(s *domain.State) error { s.Admin.Username = "after"; return nil }); err == nil {
		t.Fatal("expected primary rename failure")
	}
	if got := st.State().Admin.Username; got != "before" {
		t.Fatalf("memory username = %q", got)
	}
	after, err := os.ReadFile(st.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("rename failure changed primary")
	}
	if _, err := os.Stat(st.StatePath() + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("primary temp not cleaned: %v", err)
	}
	renameStateFile = originalRename
	if err := st.Update(func(s *domain.State) error { s.Admin.Username = "after"; return nil }); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if got := st.State().Admin.Username; got != "after" {
		t.Fatalf("retry username = %q", got)
	}
}

func TestSaveBackupRenameFailureKeepsPrimaryAndMemory(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *domain.State) error { s.Admin.Username = "before"; return nil }); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(st.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	originalRename := renameStateFile
	renameStateFile = func(oldpath, newpath string) error {
		if strings.HasSuffix(newpath, ".backup") {
			return errors.New("injected backup rename failure")
		}
		return os.Rename(oldpath, newpath)
	}
	defer func() { renameStateFile = originalRename }()
	if err := st.Update(func(s *domain.State) error { s.Admin.Username = "after"; return nil }); err == nil {
		t.Fatal("expected backup rename failure")
	}
	if got := st.State().Admin.Username; got != "before" {
		t.Fatalf("memory username = %q", got)
	}
	after, err := os.ReadFile(st.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("backup rename failure changed primary")
	}
	for _, suffix := range []string{".tmp", ".backup.tmp"} {
		if _, err := os.Stat(st.StatePath() + suffix); !os.IsNotExist(err) {
			t.Fatalf("%s not cleaned: %v", suffix, err)
		}
	}
	renameStateFile = originalRename
	if err := st.Update(func(s *domain.State) error { s.Admin.Username = "after"; return nil }); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if got := st.State().Admin.Username; got != "after" {
		t.Fatalf("retry username = %q", got)
	}
}

func TestSaveReadsPrimaryErrorAbortsBeforeBackup(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *domain.State) error { s.Admin.Username = "before"; return nil }); err != nil {
		t.Fatal(err)
	}
	// Replace the primary with a directory so ReadFile fails with EISDIR,
	// which is neither a missing file nor a usable snapshot.
	primary := st.StatePath()
	if err := os.Remove(primary); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(primary, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *domain.State) error { s.Admin.Username = "after"; return nil }); err == nil {
		t.Fatal("expected primary read error")
	}
	if got := st.State().Admin.Username; got != "before" {
		t.Fatalf("memory username = %q", got)
	}
	if _, err := os.Stat(st.StatePath() + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("primary temp not cleaned: %v", err)
	}
}
