package contract_test

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/David-Xilo/safehouse-kit/contract"
	"github.com/David-Xilo/safehouse-kit/go/schematest"
)

// schemaFor maps a fixture's file-name prefix to the schema it must match. Longer
// prefixes come first, since "batch-status-" also starts like "status-" would not.
var schemaFor = []struct{ prefix, schema string }{
	{"batch-status-", "batch-status.schema.json"},
	{"status-", "status.schema.json"},
	{"healthz-", "healthz.schema.json"},
	{"manifest-", "manifest.schema.json"},
	{"error-", "error.schema.json"},
	{"page-", "page.schema.json"},
	{"ocsf-detection-finding-", "detection_finding.schema.json"},
	{"attention-", "attention.schema.json"},
	{"runs-", "runs.schema.json"},
}

func TestEveryFixtureMatchesItsSchema(t *testing.T) {
	entries, err := fs.ReadDir(contract.Files, "fixtures")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".txt") {
			continue // Prometheus text has no JSON Schema
		}
		schema := ""
		for _, m := range schemaFor {
			if strings.HasPrefix(name, m.prefix) {
				schema = m.schema
				break
			}
		}
		if schema == "" {
			t.Errorf("%s: no schema for this fixture name", name)
			continue
		}
		data, err := contract.Files.ReadFile("fixtures/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(name, ".toml") {
			data = tomlToJSON(t, name, data)
		}
		s := schematest.Contract
		if strings.HasPrefix(name, "ocsf-") {
			s = schematest.OCSF
		}
		if err := s(t, schema).Validate(data); err != nil {
			t.Errorf("%s against %s: %v", name, schema, err)
		}
		checked++
	}
	if checked < 20 {
		t.Fatalf("checked %d fixtures, want at least 20", checked)
	}
}

// The error and page schemas are loose on purpose (extra error fields, any items), so
// check that they still reject the shapes a client could not read.
func TestErrorAndPageRejectUnreadableBodies(t *testing.T) {
	for _, c := range []struct{ schema, doc string }{
		{"error.schema.json", `{"message": "bad cursor"}`},
		{"error.schema.json", `{"error": ""}`},
		{"page.schema.json", `{"items": []}`},
		{"page.schema.json", `{"items": {}, "next_cursor": null}`},
		{"page.schema.json", `{"items": [], "next_cursor": null, "total": 3}`},
	} {
		if err := schematest.Contract(t, c.schema).Validate([]byte(c.doc)); err == nil {
			t.Errorf("%s accepted %s", c.schema, c.doc)
		}
	}
}

// The command, attention, runs and MCP shapes reject what the gateway or the console could not act on.
func TestCommandsAttentionAndRunsRejectBadShapes(t *testing.T) {
	manifest := func(command string) string {
		return `{"contract_version": "0.1", "name": "x", "code": "XX", "version": "1", "kind": "batch",
			"language": "go", "status_command": ["x"], "commands": {"c": ` + command + `}}`
	}
	reads := func(read string) string {
		return `{"contract_version": "0.1", "name": "x", "code": "XX", "version": "1", "kind": "batch",
			"language": "go", "status_command": ["x"], "read_commands": {"findings": ` + read + `}}`
	}
	daemon := func(ops string) string {
		return `{"contract_version": "0.1", "name": "x", "code": "XX", "version": "1", "kind": "daemon",
			"language": "go", "service_unit": "x.service", "base_url": "http://127.0.0.1:1",
			"openapi_url": "http://127.0.0.1:1/openapi.json", "mcp_operations": ` + ops + `}`
	}
	for _, c := range []struct{ schema, doc string }{
		{"manifest.schema.json", manifest(`{"tier": "confirm"}`)},
		{"manifest.schema.json", manifest(`{"tier": "confirm", "argv": ["x"], "route": {"method": "POST", "path": "/x"}}`)},
		{"manifest.schema.json", manifest(`{"tier": "maybe", "argv": ["x"]}`)},
		{"manifest.schema.json", manifest(`{"tier": "typed", "argv": ["x", "{name}"], "params": {"name": {"pattern": "^a$"}}}`)},
		{"manifest.schema.json", manifest(`{"tier": "safe", "argv": ["x", "{id}"], "params": {"id": {}}}`)},
		{"manifest.schema.json", manifest(`{"tier": "safe", "route": {"method": "GET", "path": "/x"}}`)},
		{"manifest.schema.json", manifest(`{"tier": "safe", "argv": ["x"], "body": "json"}`)},
		{"manifest.schema.json", manifest(`{"tier": "safe", "route": {"method": "POST", "path": "/x"}, "body": "text"}`)},
		{"manifest.schema.json", manifest(`{"tier": "safe", "argv": ["x"], "title": ""}`)},
		{"manifest.schema.json", manifest(`{"tier": "safe", "argv": ["x"], "title": "Add\nnote"}`)},
		{"manifest.schema.json", manifest(`{"tier": "safe", "route": {"method": "DELETE", "path": "/x"}, "body": "json"}`)},
		{"manifest.schema.json", manifest(`{"tier": "safe", "route": {"method": "POST", "path": "/x"}, "body": "json", "inverse": "y"}`)},
		{"manifest.schema.json", reads(`{"argv": ["x", "list"]}`)},
		{"manifest.schema.json", reads(`{"description": "Every finding"}`)},
		{"manifest.schema.json", reads(`{"argv": ["x", "list"], "description": ""}`)},
		{"manifest.schema.json", reads(`{"argv": ["x", "list"], "description": "Every finding", "params": {}}`)},
		{"manifest.schema.json", daemon(`[]`)},
		{"manifest.schema.json", daemon(`["Alerts"]`)},
		{"manifest.schema.json", daemon(`["alerts", "alerts"]`)},
		{"manifest.schema.json", strings.TrimSuffix(reads(`["x", "list"]`), "}") + `, "mcp_operations": ["alerts"]}`},
		{"attention.schema.json", `{"items": [{"uid": "a", "title": "t", "module": "x", "entities": [{"kind": "finding", "id": "a"}]}], "next_cursor": null}`},
		{"attention.schema.json", `{"items": [{"uid": "a", "module": "x"}], "next_cursor": null}`},
		{"attention.schema.json", `{"items": [{"uid": "a", "title": "t", "module": "x", "severity_id": 7}], "next_cursor": null}`},
		{"runs.schema.json", `{"module": "x", "runs": [{"id": "1", "started": null, "finished": null}]}`},
		{"runs.schema.json", `{"module": "x", "runs": [{"id": "1", "started": null, "finished": null, "outcome": "blocked"}]}`},
	} {
		if err := schematest.Contract(t, c.schema).Validate([]byte(c.doc)); err == nil {
			t.Errorf("%s accepted %s", c.schema, c.doc)
		}
	}
	// The same manifest with a well-formed command passes, so the cases above fail for
	// the reason they name.
	ok := manifest(`{"tier": "safe", "argv": ["x", "{id}"], "params": {"id": {"pattern": "^[0-9]+$"}}}`)
	if err := schematest.Contract(t, "manifest.schema.json").Validate([]byte(ok)); err != nil {
		t.Errorf("a valid command: %v", err)
	}
	ok = manifest(`{"tier": "safe", "title": "Add note", "route": {"method": "POST", "path": "/x"}, "body": "json"}`)
	if err := schematest.Contract(t, "manifest.schema.json").Validate([]byte(ok)); err != nil {
		t.Errorf("a valid command with a body: %v", err)
	}
	ok = reads(`{"argv": ["x", "list"], "description": "Every finding"}`)
	if err := schematest.Contract(t, "manifest.schema.json").Validate([]byte(ok)); err != nil {
		t.Errorf("a described read: %v", err)
	}
	ok = daemon(`["alerts", "alert"]`)
	if err := schematest.Contract(t, "manifest.schema.json").Validate([]byte(ok)); err != nil {
		t.Errorf("a daemon's MCP operations: %v", err)
	}
	ok = `{"items": [{"uid": "a", "title": "t", "module": "x", "entities": [{"kind": "finding", "id": "x/a"}]}], "next_cursor": null}`
	if err := schematest.Contract(t, "attention.schema.json").Validate([]byte(ok)); err != nil {
		t.Errorf("a finding entity: %v", err)
	}
}

func TestSchemaIDsNameTheContractVersion(t *testing.T) {
	entries, err := fs.ReadDir(contract.Files, "schemas")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := contract.Files.ReadFile("schemas/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			ID string `json:"$id"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		want := "https://safehouse.local/contract/" + contract.Version + "/" + e.Name()
		if doc.ID != want {
			t.Errorf("%s: $id %q, want %q", e.Name(), doc.ID, want)
		}
	}
}

func tomlToJSON(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var v map[string]any
	if _, err := toml.Decode(string(data), &v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
