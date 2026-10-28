package batch_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

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

func TestRuleTallyPrintsTheContractRows(t *testing.T) {
	now := time.Date(2099, 1, 31, 23, 59, 0, 0, time.UTC)
	var tally batch.RuleTally
	tally.Add("ex.rule_b", now, 3, "")
	tally.Add("ex.rule_a", now.Add(-time.Hour), 3, "benign")
	tally.Add("ex.rule_a", now.Add(-2*time.Hour), 3, "benign")
	tally.Add("ex.rule_a", time.Date(2099, 1, 2, 0, 0, 0, 0, time.FixedZone("x", 3600)), 4, "test") // 01-01 in UTC, too old
	tally.Add("ex.rule_a", time.Date(2099, 1, 2, 0, 0, 0, 0, time.UTC), 4, "routine")               // the oldest day kept
	tally.Add("ex.rule_a", now.AddDate(0, 0, 1), 4, "real")                                         // not yet
	got := tally.Rows(now)
	want := []batch.RuleCount{
		{Rule: "ex.rule_a", Day: "2099-01-02", SeverityID: 4, Label: "routine", Count: 1},
		{Rule: "ex.rule_a", Day: "2099-01-31", SeverityID: 3, Label: "benign", Count: 2},
		{Rule: "ex.rule_b", Day: "2099-01-31", SeverityID: 3, Label: batch.LabelNone, Count: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rows\n got %+v\nwant %+v", got, want)
	}

	schema := schematest.Contract(t, "batch-status.schema.json")
	s := batch.Status{ContractVersion: batch.ContractVersion, Module: "example", Version: "0.1.0", State: "idle", Waiting: []batch.Waiting{}}
	for name, c := range map[string]struct {
		rows  []batch.RuleCount
		field bool
	}{
		"a tool without findings": {nil, false},
		"no findings yet":         {new(batch.RuleTally).Rows(now), true},
		"findings":                {got, true},
	} {
		s.RuleCounts = c.rows
		data, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(data); err != nil {
			t.Errorf("%s: %v\n%s", name, err, data)
		}
		if has := strings.Contains(string(data), `"rule_counts":`); has != c.field {
			t.Errorf("%s: rule_counts printed %v, want %v\n%s", name, has, c.field, data)
		}
	}
}

// The schema refuses a row the hub could not count: a missing or spaced rule key, a
// label outside the vocabulary, a zero count, a local time for the day.
func TestRuleCountsRejectBadRows(t *testing.T) {
	schema := schematest.Contract(t, "batch-status.schema.json")
	status := func(row string) string {
		return `{"contract_version": "0.1", "module": "x", "version": "1", "state": "idle", "last_run": null,
			"waiting": [], "rule_counts": [` + row + `]}`
	}
	for _, row := range []string{
		`{"day": "2099-01-01", "severity_id": 3, "label": "none", "count": 1}`,
		`{"rule": "", "day": "2099-01-01", "severity_id": 3, "label": "none", "count": 1}`,
		`{"rule": "a rule", "day": "2099-01-01", "severity_id": 3, "label": "none", "count": 1}`,
		`{"rule": "a\"b", "day": "2099-01-01", "severity_id": 3, "label": "none", "count": 1}`,
		`{"rule": "r", "day": "2099-01-01", "severity_id": 3, "label": "resolved", "count": 1}`,
		`{"rule": "r", "day": "2099-01-01", "severity_id": 3, "label": "none", "count": 0}`,
		`{"rule": "r", "day": "2099-01-01T00:00:00Z", "severity_id": 3, "label": "none", "count": 1}`,
		`{"rule": "r", "day": "2099-01-01", "severity_id": 7, "label": "none", "count": 1}`,
		`{"rule": "r", "day": "2099-01-01", "severity_id": 3, "label": "none", "count": 1, "open": 1}`,
	} {
		if schema.Validate([]byte(status(row))) == nil {
			t.Errorf("accepted %s", row)
		}
	}
	ok := `{"rule": "sigma:0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9", "day": "2099-01-01", "severity_id": 3, "label": "none", "count": 1}`
	if err := schema.Validate([]byte(status(ok))); err != nil {
		t.Errorf("a valid row: %v", err)
	}
}
