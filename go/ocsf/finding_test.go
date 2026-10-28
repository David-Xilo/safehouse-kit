package ocsf

import (
	"reflect"

	"encoding/json"
	"github.com/David-Xilo/safehouse-kit/contract"
	"testing"
	"time"

	"github.com/David-Xilo/safehouse-kit/go/schematest"
)

func TestNewFindingValidatesAsOCSF2004(t *testing.T) {
	at := time.Date(2099, 1, 1, 12, 0, 0, 0, time.UTC)
	f := NewFinding(
		NewMetadata("example-guard", "0.1.0", []string{"datetime", "host"}, at.Add(time.Minute)),
		Device{TypeID: DeviceDesktop, Hostname: "workstation"},
		at, SeverityHigh,
		FindingInfo{UID: "ex-1", Title: "Example finding", Types: []string{"example"},
			Analytic: &Analytic{TypeID: AnalyticRule, UID: "ex.rule", Name: "Example rule"}},
	)
	f.IsAlert = true
	f.Actor = &Actor{Process: &Process{PID: 4242, Name: "sh", CmdLine: "sh -c true"}}
	f.Unmapped = map[string]any{"ex": map[string]any{"rule": "r1"}}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	schema := schematest.OCSF(t, "detection_finding.schema.json")
	if err := schema.Validate(data); err != nil {
		t.Fatalf("%s\n%v", data, err)
	}
	if f.TypeUID != 200401 || f.TimeDT != "2099-01-01T12:00:00Z" {
		t.Errorf("type_uid %d, time_dt %s", f.TypeUID, f.TimeDT)
	}
	// The export must still reject a finding without finding_info.
	var doc map[string]any
	_ = json.Unmarshal(data, &doc)
	delete(doc, "finding_info")
	bad, _ := json.Marshal(doc)
	if schema.Validate(bad) == nil {
		t.Error("a finding without finding_info validated")
	}
}

// pkg-guard, the first writer, switches to these types without changing its output.
func TestPkgGuardFindingRoundTrips(t *testing.T) {
	data, err := contract.Files.ReadFile("fixtures/ocsf-detection-finding-pkg-guard.json")
	if err != nil {
		t.Fatal(err)
	}
	var f DetectionFinding
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	_ = json.Unmarshal(data, &want)
	_ = json.Unmarshal(out, &got)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("round trip changed the event:\n%s", out)
	}
}

// Every finding names its rule and carries at most one label from the vocabulary; the
// contract's finding schema fails one that does not, while the OCSF export alone lets
// it through.
func TestFindingNamesItsRule(t *testing.T) {
	at := time.Date(2099, 1, 1, 12, 0, 0, 0, time.UTC)
	f := NewFinding(
		NewMetadata("example-guard", "0.1.0", []string{"datetime", "host"}, at),
		Device{TypeID: DeviceDesktop, Hostname: "workstation"},
		at, SeverityMedium,
		FindingInfo{UID: "ex-1", Title: "Example finding", Analytic: &Analytic{TypeID: AnalyticRule, UID: "ex.rule"}},
	)
	ocsf := schematest.OCSF(t, "detection_finding.schema.json")
	contractSchema := schematest.Contract(t, "finding.schema.json")
	for _, label := range []string{"", LabelBenign, LabelReal, LabelRoutine, LabelTest} {
		g := f
		if label != "" {
			g.Metadata.Labels = []string{label}
		}
		data, _ := json.Marshal(g)
		if err := ocsf.Validate(data); err != nil {
			t.Errorf("label %q, OCSF: %v", label, err)
		}
		if err := contractSchema.Validate(data); err != nil {
			t.Errorf("label %q, contract: %v", label, err)
		}
	}
	for name, change := range map[string]func(*DetectionFinding){
		"no analytic":       func(g *DetectionFinding) { g.FindingInfo.Analytic = nil },
		"no rule key":       func(g *DetectionFinding) { g.FindingInfo.Analytic = &Analytic{TypeID: AnalyticRule} },
		"a spaced rule key": func(g *DetectionFinding) { g.FindingInfo.Analytic = &Analytic{TypeID: AnalyticRule, UID: "ex rule"} },
		"an unknown label":  func(g *DetectionFinding) { g.Metadata.Labels = []string{"resolved"} },
		"two labels":        func(g *DetectionFinding) { g.Metadata.Labels = []string{LabelRoutine, LabelTest} },
	} {
		g := f
		change(&g)
		data, _ := json.Marshal(g)
		if contractSchema.Validate(data) == nil {
			t.Errorf("%s: the contract accepted\n%s", name, data)
		}
		if name == "no analytic" && ocsf.Validate(data) != nil {
			t.Errorf("%s: the OCSF export refused it, so the contract adds nothing", name)
		}
	}
}
