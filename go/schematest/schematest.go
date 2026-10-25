// Package schematest compiles JSON Schemas for tests: a module's own schema files, and the
// contract schemas embedded in safehouse-core.
package schematest

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/David-Xilo/safehouse-kit/contract"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Schema validates JSON documents against one schema.
type Schema struct{ s *jsonschema.Schema }

// Compile loads a schema file (draft-07 for the OCSF exports, 2020-12 for the contract).
func Compile(t *testing.T, path string) Schema {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	return compile(t, path, "file://"+filepath.ToSlash(abs), data)
}

// Contract loads one of the contract's schemas by file name, such as
// "batch-status.schema.json", from the copy embedded in this module.
func Contract(t *testing.T, name string) Schema {
	t.Helper()
	data, err := contract.Files.ReadFile("schemas/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return compile(t, name, "https://safehouse.local/contract/"+contract.Version+"/"+name, data)
}

func compile(t *testing.T, name, url string, data []byte) Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(url, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(url)
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	return Schema{s: s}
}

// Validate returns the validation error for one JSON document, or nil.
func (s Schema) Validate(data []byte) error {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	return s.s.Validate(inst)
}

// OCSF loads one of the OCSF 1.9.0 class exports shared through the contract, such as
// "detection_finding.schema.json", from the copy embedded in this module.
func OCSF(t *testing.T, name string) Schema {
	t.Helper()
	data, err := contract.Files.ReadFile("ocsf/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return compile(t, name, "https://safehouse.local/contract/ocsf/"+name, data)
}
