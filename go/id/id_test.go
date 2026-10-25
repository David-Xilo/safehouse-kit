package id_test

import (
	"encoding/json"
	"testing"

	"github.com/David-Xilo/safehouse-kit/contract"
	"github.com/David-Xilo/safehouse-kit/go/id"
)

// The shared cases, which Rust's id::process_uid passes too (rust/tests/id.rs).
func TestProcessUIDPassesTheSharedCases(t *testing.T) {
	data, err := contract.Files.ReadFile("ids/process-uid.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []struct {
			BootID     string `json:"boot_id"`
			PID        uint32 `json:"pid"`
			StartTicks uint64 `json:"start_ticks"`
			UID        string `json:"uid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) < 5 {
		t.Fatalf("read %d cases, want at least 5", len(file.Cases))
	}
	for _, c := range file.Cases {
		if got := id.ProcessUID(c.BootID, c.PID, c.StartTicks); got != c.UID {
			t.Errorf("ProcessUID(%q, %d, %d) = %s, want %s", c.BootID, c.PID, c.StartTicks, got, c.UID)
		}
	}
}
