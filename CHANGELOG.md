# Changelog

One line per tag, newest first. A tag releases the Go module, the Rust crate and the
contract together. `contract_version` is `0.1` in every release so far: each contract
change was additive. "Rules" marks a change to the redaction rules or their cases.

- `v0.10.1` (2026-10-28): the fake hex token in the Rust token test carries the secret scanners' inline markers, so the public export's secrets gate passes, and the token test no longer overwrites its own read-only file, so it passes for a user who is not root. Code, API and the contract unchanged.
- `v0.10.0` (2026-10-26): Rust `token::WriteToken` behind the feature `write-token`: loads the local write token from a file the caller owns with no group or other access (a symlink, a FIFO or a malformed token is refused), checks `Authorization: Bearer` in constant time (`Refused`), and makes and checks the console's session cookie, HMAC-SHA256 under a key derived from the token, so a new token ends every session (`Session`, `SessionRefused`, `SESSION_COOKIE`). Go and the contract unchanged.
- `v0.9.0` (2026-10-26): findings name their rule and carry one label: `finding.schema.json` (rule key `finding_info.analytic.uid`; `metadata.labels`, at most one of `benign`, `real`, `routine`, `test`), batch status `rule_counts` and the daemon gauge `<prefix>_rule_findings`. Go `ocsf.Analytic`, `FindingInfo.Analytic`, `Metadata.Labels`, the `Label*` constants, `batch.RuleCount` and `batch.RuleTally`; Rust `ocsf::label`, `Metadata.labels`, `status::RuleCount`, `BatchStatus.rule_counts`, `status::rule_findings_metric` and `schema::Schema::Finding`. Contract `0.1`: additive.
- `v0.8.1` (2026-10-25): the Apache-2.0 licence, a README for the public copy `safehouse-kit`, and comments and schema descriptions without internal task references. API, rule patterns and cases unchanged.
- `v0.8.0` (2026-10-16): Rust `local::Client`, a schema-checked chat with a pinned model on a loopback Ollama, behind the feature `local-model`; pins in `rust/local-tiers.toml`.
- `v0.7.0` (2026-10-15): manifest `mcp_operations`; a daemon's `GET` operation is an MCP tool only when listed there.
- `v0.6.0` (2026-10-15): the contract's MCP part (described read commands as gateway tools, a read command as a table with `argv` and `description`); attention entity kinds `session`, `kernel_session` and `finding`; `argv` commands for daemons; Go `go/id.ProcessUID` and `contract/ids/process-uid.json`, equal to Rust's `id::process_uid`.
- `v0.5.2` (2026-10-14): `go/jev` pings its HTTP/2 connections and closes one that does not answer, so a retry dials again. API unchanged.
- `v0.5.1` (2026-10-10): the Rust redactor reads RE2's `\w`, `\d`, `\s` and `\b` as ASCII, as Go does; loading the rules costs 17 MiB instead of 554 MiB. Rules: the ASCII note and one case. API unchanged.
- `v0.5.0` (2026-10-07): Go `go/jev`, one client for Jev's Noul, Score and Choice questions.
- `v0.4.0` (2026-10-07): a command's optional `title` (button label, at most 40 characters) and `body = "json"`.
- `v0.3.0` (2026-10-01): manifest `commands` and `stream_url`, live streams, `attention.schema.json` and `runs.schema.json`; Rust `schema::Schema` gains `Attention` and `Runs`.
- `v0.2.1` (2026-10-01): the Rust crate in `rust/` (`id`, `ocsf`, `jsonl`, `status`, `redact`, `schema`). Go unchanged.
- `v0.2.0` (2026-10-01): Go `go/redact` and the Detection Finding 2004 types in `go/ocsf`, with `contract/ocsf/detection_finding.schema.json`. Rules: first release, ours and gitleaks', with `cases.json`.
- `v0.1.1` (2026-09-29): contract 0.1 accepted; adds the `error` body, `{items, next_cursor}` pages and the unknown-metric rule (`error.schema.json`, `page.schema.json`).
- `v0.1.0` (2026-09-29): contract 0.1 draft (event envelope, `status`, `healthz`, batch status, manifest) with schemas and fixtures; Go `contract`, `go/ocsf`, `go/batch`, `go/utc` and `go/schematest`.
