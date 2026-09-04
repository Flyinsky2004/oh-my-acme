package store

import (
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
