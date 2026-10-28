// Package batch holds the batch-tool status of the safehouse module contract
// (contract/README.md, "Batch tools"): what `<tool> status --json` prints.
package batch

import (
	"cmp"
	"slices"
	"time"

	"github.com/David-Xilo/safehouse-kit/contract"
)

// ContractVersion is the contract version a batch status carries.
const ContractVersion = contract.Version

type Status struct {
	ContractVersion string    `json:"contract_version"`
	Module          string    `json:"module"`
	Version         string    `json:"version"`
	State           string    `json:"state"`
	LastRun         *LastRun  `json:"last_run"`
	Waiting         []Waiting `json:"waiting"`
	// RuleCounts is printed by a tool that writes findings, as an empty list when it
	// holds none; nil leaves it out. Rows come from RuleTally.Rows.
	RuleCounts []RuleCount `json:"rule_counts,omitzero"`
}

type LastRun struct {
	ID       string   `json:"id"`
	Started  string   `json:"started"`
	Finished *string  `json:"finished"`
	Outcome  string   `json:"outcome"`
	CostUSD  *float64 `json:"cost_usd"`
	Record   string   `json:"record"`
}

type Waiting struct {
	What  string `json:"what"`
	Why   string `json:"why"`
	Count *int   `json:"count,omitempty"`
}

// RuleCount is one row of rule_counts: the findings of one rule first raised on one UTC
// day, at one severity, that carry one label now.
type RuleCount struct {
	Rule       string `json:"rule"`        // finding_info.analytic.uid
	Day        string `json:"day"`         // YYYY-MM-DD, UTC
	SeverityID int    `json:"severity_id"` // when the finding was raised
	Label      string `json:"label"`       // a label from go/ocsf, or LabelNone
	Count      int    `json:"count"`
}

// LabelNone is the label column of findings that have no label.
const LabelNone = "none"

// RuleCountDays is how many UTC days rule_counts covers, today included.
const RuleCountDays = 30

// RuleTally counts findings into rule_counts rows. The zero value is ready to use.
type RuleTally struct {
	counts map[RuleCount]int
}

// Add counts one finding: its rule key, when it was first raised, its severity then and
// its label now ("" for none).
func (t *RuleTally) Add(rule string, firstSeen time.Time, severityID int, label string) {
	if label == "" {
		label = LabelNone
	}
	if t.counts == nil {
		t.counts = map[RuleCount]int{}
	}
	key := RuleCount{Rule: rule, Day: firstSeen.UTC().Format(time.DateOnly), SeverityID: severityID, Label: label}
	t.counts[key]++
}

// Rows returns the counts of the RuleCountDays UTC days up to now's, sorted by day, rule,
// severity and label. It is never nil, so a tool that writes findings always prints the
// field.
func (t *RuleTally) Rows(now time.Time) []RuleCount {
	today := now.UTC().Truncate(24 * time.Hour)
	first := today.AddDate(0, 0, 1-RuleCountDays).Format(time.DateOnly)
	last := today.Format(time.DateOnly)
	rows := []RuleCount{}
	for key, n := range t.counts {
		if key.Day < first || key.Day > last {
			continue
		}
		key.Count = n
		rows = append(rows, key)
	}
	slices.SortFunc(rows, func(a, b RuleCount) int {
		return cmp.Or(cmp.Compare(a.Day, b.Day), cmp.Compare(a.Rule, b.Rule),
			cmp.Compare(a.SeverityID, b.SeverityID), cmp.Compare(a.Label, b.Label))
	})
	return rows
}
