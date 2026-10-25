package ocsf

import (
	"time"

	"github.com/David-Xilo/safehouse-kit/go/utc"
)

// OCSF 1.9.0 Detection Finding (2004), shared by the Go writers of the class:
// pkg-guard first, then agent-guard and host-adapters. Only fields a writer fills are
// defined; contract/ocsf/detection_finding.schema.json is the official export the
// fixtures and every writer's output validate against. A writer's own fields go under
// Unmapped, keyed by its module code in lower case.
const (
	ClassDetectionFinding = 2004
	CategoryFindings      = 2

	ActivityCreate = 1
	ActivityUpdate = 2
	ActivityClose  = 3

	SeverityUnknown       = 0
	SeverityInformational = 1
	SeverityLow           = 2
	SeverityMedium        = 3
	SeverityHigh          = 4
	SeverityCritical      = 5
	SeverityFatal         = 6

	StatusNew        = 1
	StatusInProgress = 2
	StatusSuppressed = 3
	StatusResolved   = 4

	DeviceDesktop = 2
)

type FindingInfo struct {
	UID   string   `json:"uid"`
	Title string   `json:"title"`
	Types []string `json:"types,omitempty"`
	Desc  string   `json:"desc,omitempty"`
}

type Malware struct {
	UID               string `json:"uid,omitempty"`
	Name              string `json:"name"`
	ClassificationIDs []int  `json:"classification_ids"`
	Provider          string `json:"provider,omitempty"`
}

type Process struct {
	PID     int    `json:"pid,omitempty"`
	UID     string `json:"uid,omitempty"`
	Name    string `json:"name,omitempty"`
	CmdLine string `json:"cmd_line,omitempty"` // redacted with go/redact before it is written
}

type Actor struct {
	Process *Process `json:"process,omitempty"`
}

type Remediation struct {
	Desc string `json:"desc"`
}

// DetectionFinding is OCSF class 2004.
type DetectionFinding struct {
	ActivityID  int            `json:"activity_id"`
	CategoryUID int            `json:"category_uid"`
	ClassUID    int            `json:"class_uid"`
	TypeUID     int            `json:"type_uid"`
	SeverityID  int            `json:"severity_id"`
	StatusID    int            `json:"status_id"`
	IsAlert     bool           `json:"is_alert,omitempty"`
	Time        int64          `json:"time"`
	TimeDT      string         `json:"time_dt"`
	Message     string         `json:"message,omitempty"`
	Metadata    Metadata       `json:"metadata"`
	Device      Device         `json:"device"`
	Actor       *Actor         `json:"actor,omitempty"`
	FindingInfo FindingInfo    `json:"finding_info"`
	Malware     []Malware      `json:"malware,omitempty"`
	Remediation *Remediation   `json:"remediation,omitempty"`
	Unmapped    map[string]any `json:"unmapped,omitempty"`
}

// NewFinding returns a new (status New) finding created at observed: the class fields,
// time and severity set, the rest left to the writer.
func NewFinding(meta Metadata, device Device, observed time.Time, severity int, info FindingInfo) DetectionFinding {
	return DetectionFinding{
		ActivityID:  ActivityCreate,
		CategoryUID: CategoryFindings,
		ClassUID:    ClassDetectionFinding,
		TypeUID:     ClassDetectionFinding*100 + ActivityCreate,
		SeverityID:  severity,
		StatusID:    StatusNew,
		Time:        utc.Millis(observed),
		TimeDT:      utc.Format(observed),
		Metadata:    meta,
		Device:      device,
		FindingInfo: info,
	}
}
