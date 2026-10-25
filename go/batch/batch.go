// Package batch holds the batch-tool status of the safehouse module contract
// (contract/README.md, "Batch tools"): what `<tool> status --json` prints.
package batch

import "github.com/David-Xilo/safehouse-kit/contract"

// ContractVersion is the contract version a batch status carries.
const ContractVersion = contract.Version

type Status struct {
	ContractVersion string    `json:"contract_version"`
	Module          string    `json:"module"`
	Version         string    `json:"version"`
	State           string    `json:"state"`
	LastRun         *LastRun  `json:"last_run"`
	Waiting         []Waiting `json:"waiting"`
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
