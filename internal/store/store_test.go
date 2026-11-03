package store

import (
	"errors"
	"os"
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
