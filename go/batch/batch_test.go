package batch_test

import (
	"encoding/json"
	"testing"

	"github.com/David-Xilo/safehouse-kit/go/batch"
	"github.com/David-Xilo/safehouse-kit/go/schematest"
)

func TestStatusMatchesTheContract(t *testing.T) {
	schema := schematest.Contract(t, "batch-status.schema.json")
	finished := "2026-09-29T12:31:00.5Z"
	n := 3
	for name, s := range map[string]batch.Status{
		"before the first run": {ContractVersion: batch.ContractVersion, Module: "example", Version: "0.1.0", State: "idle", Waiting: []batch.Waiting{}},
		"after a run": {
			ContractVersion: batch.ContractVersion, Module: "example", Version: "0.1.0", State: "waiting",
			LastRun: &batch.LastRun{ID: "r1", Started: "2026-09-29T12:30:00Z", Finished: &finished, Outcome: "succeeded", Record: "/tmp/r1.json"},
			Waiting: []batch.Waiting{{What: "open findings", Why: "not yet removed", Count: &n}},
		},
	} {
		data, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(data); err != nil {
			t.Errorf("%s: %v\n%s", name, err, data)
		}
	}
}
