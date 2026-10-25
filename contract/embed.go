// Package contract embeds the safehouse module contract: its JSON Schemas and golden
// fixtures, the shared redaction rules, the shared OCSF schema exports and the shared
// identity cases. README.md in this directory holds the shapes they encode.
package contract

import "embed"

// Version is the contract version every status, batch status and manifest carries.
const Version = "0.1"

// Files holds schemas/*.json, fixtures/*, rules/*, ocsf/* and ids/*, read with paths such
// as "schemas/batch-status.schema.json" or "rules/sniff.toml".
//
//go:embed schemas/*.json fixtures/* rules/* ocsf/*.json ids/*.json
var Files embed.FS
