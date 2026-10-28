# Module contract

Version 0.1. This file holds the exact shapes; what each core release changed is in
[CHANGELOG.md](../CHANGELOG.md). The machine-readable parts are in [`schemas/`](schemas)
and [`fixtures/`](fixtures): JSON Schemas (2020-12) and synthetic fixtures. The Go package
`contract` ([`embed.go`](embed.go)) embeds both, and the core's tests validate every
fixture against its schema.

The contract is language-neutral. A module meets it through files, HTTP and
schemas. Shared code in safehouse-core is optional: each language may validate with its
own tools, and conformance is always proved against these schemas and fixtures.

## Versioning

- `contract_version` is `"0.1"` in every `status`, batch status and manifest.
- A breaking change raises the version and lists what each module must change.
- An additive clause keeps `"0.1"`; no module has to change for it.
- A validator older than the core release that added an optional field refuses that
  field. A module declares the field only once every reader of its documents (the
  gateway, the hub) uses that release or a later one:

  | Field | Core release |
  |---|---|
  | Manifest `commands`, `stream_url` | `v0.3.0` |
  | Command `title`, `body` | `v0.4.0` |
  | A read command as a table with `argv` and `description` | `v0.6.0` |
  | Manifest `mcp_operations` | `v0.7.0` |
  | Batch status `rule_counts` | `v0.9.0` |

## Events

Every event is one OCSF 1.9.0 object, one per line in JSONL, and also in the module's
own store.

| Field | Rule |
|---|---|
| `metadata.version` | `"1.9.0"` |
| `metadata.profiles` | `datetime` and `host`; add `linux` when the event uses Linux fields |
| `metadata.uid` | UUIDv7, made by the writer |
| `metadata.product.name` | The module's repository name (e.g. `traffic-sniffer`); the same as `module` in `status` |
| `metadata.product.version` | The module's version |
| `time`, `time_dt` | When the fact happened or was captured, UTC. `time` is epoch ms (OCSF); `time_dt` keeps nanoseconds |
| `metadata.processed_time`, `processed_time_dt` | When the module processed it, UTC |
| `unmapped.<code>.*` | The only place for fields OCSF lacks, under the module code in lower case (the sniffer uses `unmapped.sniff`) |
| `device` | The host that observed the event: `hostname` or `uid` |

Further rules:
- **Facts and inferences stay apart.** An observed fact (a process started) and a
  judgment about it (it looks malicious) are separate events; findings reference the
  facts by `metadata.uid`.
- **Schema tests.** Each class a module writes has golden fixtures validated against
  the official schema export with the module's profiles:
  `https://schema.ocsf.io/schema/1.9.0/classes/<class>?profiles=datetime,host,linux`
  (send `Accept: application/schema+json`). Without the profile filter, `cloud` and
  `osint` fields become required.
- **Redaction** runs before any event leaves the host.
  Fixtures are synthetic or redacted and reviewed.

## Ownership

- Several modules may use one OCSF class. A module is the only writer of **its own
  events**, identified by `metadata.product.name`, and of its own store.
- No module writes another module's store, JSONL or alerts. A user's feedback goes
  through the owning module's API.
- **Fact owners.** When two modules could report the same fact, one owns it and the
  other links to it by `metadata.uid` or by a shared key (such as `process.uid`):

  | Fact | Owner | Others |
  |---|---|---|
  | Process exec and exit | SNIFF | AGT, PER and PKG link to it by `process.uid` |
  | Connections, DNS, TLS, HTTP seen on the host | SNIFF | IOT and NTR read them |
  | Egress decisions | OpenSnitch adapter | SNIFF links flows to them |
  | DNS filter decisions | DNS filter adapter | IOT reads them |
  | Device commands and state | CTL | GW records only that a command passed |
  | Incidents and cross-module alerts | HUB | — |

## OCSF classes per module

Each module confirms its classes with schema-tested fixtures, and adds a class only with
fixtures.

| Module | Classes |
|---|---|
| SNIFF | 1007 Process Activity, 4001 Network Activity, 4002 HTTP Activity, 4003 DNS Activity; 2004 Detection Finding |
| SEC | 2006 Data Security Finding (a secret found), 2003 Compliance Finding (key age and strength, file modes), 6007 Scan Activity (a scan run) |
| PER | 1001 File Activity, 1006 Scheduled Job Activity, 2004 Detection Finding |
| AGT | 2004 Detection Finding; 1009 Script Activity for the audited agent command |
| PKG | 2004 Detection Finding; 2002 Vulnerability Finding and 5020 Software Info later, when a consumer exists |
| ADP | OpenSnitch → 4001 Network Activity; USBGuard → 1010 Peripheral Activity; 2004 Detection Finding |
| HUB | 2005 Incident Finding, 2004 Detection Finding |
| GW | 6003 API Activity (a command passed through) |
| LIB, LFE, CLN | None: batch tools whose output no module consumes as events |

Modules not built yet take their classes when they start, with fixtures: home control
(CTL) 6003 for commands; vulnerability triage 2002 and 5020; server adapters 4003, 5001
or 2004.

## Findings

A finding is an event of an OCSF Findings class (2003, 2004, 2006, …) that has
`finding_info`; the hub's Incident Finding (2005) is not one. Every finding names its
rule and carries at most one label, so the hub can count and judge each rule the same
way in every module. Schema: [`finding.schema.json`](schemas/finding.schema.json), which
checks these clauses only; the finding also validates against its class's OCSF export.

**Rule key.** `finding_info.analytic.uid`, with OCSF's required `analytic.type_id`
(`1`, Rule, for a written rule):
- printable ASCII without spaces, double quotes or backslashes, 1 to 200 characters;
- stable for the rule across versions and runs: it names the rule, never one finding;
- no captured data: no command line, path, host or payload. An indicator list is one rule
  or one rule per entry, by the entry's id, never by the indicator itself.

**Labels.** `metadata.labels` holds at most one of four words. A finding's label is the
one on its newest event; a finding with none is unlabelled.

| Label | Set by | Meaning |
|---|---|---|
| `benign` | the user's decision, through the module's own verb (a false-positive mark, an accept, an allow) | expected; nothing to do |
| `real` | the user's decision, through the module's own verb | it needed action |
| `routine` | code, when the finding is raised | closed at creation by a written rule for a known benign source |
| `test` | code, when the finding is raised | raised on purpose by an acceptance script |

- The event a decision writes (an update or close) carries `benign` or `real`. The user
  may relabel a `routine` finding.
- `test` is opt-in per finding: the acceptance script asks for it through a switch the
  module documents (a flag or an environment variable). It is never inferred from the
  finding, and a check that must prove the real path does not set it. Every later event of
  a test finding keeps `test`.
- "Resolved" and "acknowledged" are states, not labels: `status_id` keeps them.

**Per-rule counts.** A module that writes findings counts them per rule key, per UTC day
of first sight, per `severity_id` at creation and per label now (`none` when
unlabelled), over the last 30 UTC days, today included. A row has a count of at least 1;
rows of 0 are left out, and each (rule, day, severity, label) appears once. A batch tool
prints them as `rule_counts` in `status --json` ([Batch tools](#batch-tools)); a daemon
serves them as the `<prefix>_rule_findings` gauge in `/metrics`
([Metrics](#http-endpoints)). Counts hold rule keys and numbers only, so a reader never
needs captured data to count.

## HTTP endpoints

Daemons listen on `127.0.0.1` by default. Remote access goes through the gateway.

| Endpoint | Shape |
|---|---|
| `GET /healthz` | `200 {"status":"ok"}` when the module works; `503 {"status":"down","reason":"…"}` otherwise. Schema: [`healthz.schema.json`](schemas/healthz.schema.json). Gatus checks `[STATUS] == 200` |
| `GET /status` | Summary for launcher tiles and the gateway's `/overview`. Schema: [`status.schema.json`](schemas/status.schema.json) |
| `GET /metrics` | Prometheus text, see below |
| `GET /openapi.json` | OpenAPI 3.1 generated from code |
| Any error | See [errors](#errors-and-lists) |

**`status` fields** (all required; unknown values are `null`, never `0`):

| Field | Meaning |
|---|---|
| `contract_version`, `module`, `version` | Contract version, repository name, module version |
| `state`, `since`, `reason` | `starting`, `ok`, `degraded` or `down`; when it began; a short reason when not `ok` (optional, no payloads) |
| `last_event_time` | UTC time of the newest event |
| `counts` | Module-specific counters (events, alerts, flows …) |
| `drops`, `queue_depth` | Events lost before the store; items waiting to be written |
| `store.bytes`, `store.events` | Store size |
| `ai.mode`, `ai.provider_state`, `ai.budget` | `jev`, `local` or `off`; provider `ok`, `degraded`, `down` or `unused`; budget `used`, `cap`, `unit` (`calls`, `tokens`, `usd`) and `window` (`minute`, `day`, `run`), or `null` without AI |

All times are RFC 3339 in UTC with a `Z` suffix and up to nine fractional digits.

**Metrics.** The prefix is the module code in lower case (`sniff_`, `sec_`). Required:

| Metric | Type |
|---|---|
| `<prefix>_build_info{version,contract_version}` | gauge, always 1 |
| `<prefix>_events_total` | counter; may carry a `class_uid` label |
| `<prefix>_drops_total` | counter |
| `<prefix>_store_bytes` | gauge |

A daemon that writes findings also serves its [per-rule counts](#findings):

| Metric | Type |
|---|---|
| `<prefix>_rule_findings{rule,day,severity_id,label}` | gauge: findings of the rule key first raised on the UTC day (`YYYY-MM-DD`), at that `severity_id`, carrying that label now (`none` when unlabelled) |

A required metric whose value the module does not know is declared (`# HELP` and
`# TYPE`) with no sample. It is never a `0` sample, as in `status`, where unknown is
`null`. Example: the sniffer's `sniff_drops_total` has no sample until its store holds
capture drop samples (replays have none).

Labels never carry command lines, URLs, user names or payloads.

<a name="review-against-the-sniffer"></a>

### Errors and lists

**Errors.** Every 4xx and 5xx answer has a JSON body with a string `error`. Schema:
[`error.schema.json`](schemas/error.schema.json). Other fields may follow (the gateway's
`kind`).
- 400: a bad parameter, time or cursor. An unknown parameter should be a 400 too, so a
  typo never returns everything.
- 404: an unknown id or path.
- 503: the store or a dependency is unavailable. `healthz` keeps its own `down` body.
- 500: an internal failure, which is logged.

The message is short and never holds commands, URLs or payloads.

**Lists.** List endpoints take `limit` and an opaque `cursor`. They return
`{"items": […], "next_cursor": …}`, with `next_cursor` `null` on the last page. Schema:
[`page.schema.json`](schemas/page.schema.json); the items are the module's own shape,
typed in its OpenAPI document.
- A client passes back only a `next_cursor` it was given.
- A walk never returns an item twice, even while the module writes.
- Each module documents its default order and what a walk can miss. For example, an
  oldest-first walk misses an event recorded late with an older time.

## Batch tools

A tool without a daemon (librarian, agent-flow runs, LFE) prints `status --json`
matching [`batch-status.schema.json`](schemas/batch-status.schema.json):

| Field | Meaning |
|---|---|
| `contract_version`, `module`, `version` | As for daemons |
| `state` | `idle`, `running`, `waiting` or `failed` |
| `last_run` | `id`, `started`, `finished`, `outcome` (`succeeded`, `failed`, `waiting`, `cancelled`, `running`), `cost_usd` (`null` when unknown), `record` (path of the last-run record on disk); `null` before the first run |
| `waiting` | A list of `what`, `why` and an optional `count` |
| `rule_counts` | A tool that writes findings: its [per-rule counts](#findings), a list of `rule`, `day`, `severity_id`, `label` and `count`, empty when it holds none. Optional; see [Versioning](#versioning) |

The command exits 0 when it could report, whatever the state. A batch tool gains
HTTP endpoints only when the console needs them.

**Read commands.** Until then, a batch tool can offer more read-only data through
`read_commands` in its manifest; a daemon can too, for data its CLI reads. The
gateway runs each one on request and serves its output at
`/m/{module}/read/{name}`:
- the command is an argv array, run without a shell, with a timeout and an output cap;
  it takes no params;
- it must only read, and print one JSON document;
- its shape is the module's own, documented with a JSON Schema in its repository
  (secret-hygiene: `docs/list.schema.json` for `findings`);
- it is declared as the argv array, or as a table with `argv` and a `description` of at
  most 1,000 characters; a described read is also an [MCP](#mcp) tool.

## Manifest

Each module ships `safehouse.module.toml` once the hub or the gateway reads it. Schema:
[`manifest.schema.json`](schemas/manifest.schema.json), applied after TOML
parsing.

| Field | Required | Meaning |
|---|---|---|
| `contract_version`, `name`, `code`, `version` | yes | `code`: the module's short upper-case code (e.g. `SNIFF`) |
| `kind` | yes | `daemon` or `batch` |
| `language` | yes | `rust`, `go`, `python`, `typescript`, `c` or `cpp` |
| `service_unit`, `base_url`, `openapi_url` | daemons | systemd unit and local URLs |
| `status_command` | batch tools | The command that prints `status --json`: an argv array (preferred) or a string |
| `read_commands` | no | Named read-only commands, each an argv array, or a table with `argv` and `description`, that prints one JSON document. The gateway serves them at `/m/{module}/read/{name}` ([Batch tools](#batch-tools)) |
| `description`, `mcp_url`, `console_route`, `ocsf_classes` | no | For the launcher, gateway and console navigation |
| `mcp_operations` | no | Daemons: the `operationId`s of the `GET` operations the gateway serves as [MCP](#mcp) tools |
| `stream_url` | no | Daemons: the live stream's WebSocket URL ([Live streams](#live-streams)) |
| `commands` | no | The commands the module offers through the gateway ([Commands](#commands)) |

Examples: [`manifest-sniffer.toml`](fixtures/manifest-sniffer.toml),
[`manifest-librarian.toml`](fixtures/manifest-librarian.toml),
[`manifest-secret-hygiene.toml`](fixtures/manifest-secret-hygiene.toml),
[`manifest-mop.toml`](fixtures/manifest-mop.toml),
[`manifest-lifelog-notes.toml`](fixtures/manifest-lifelog-notes.toml).

## Commands

A module offers commands only through its manifest's `commands` table, one entry per
name. The gateway passes each command through unchanged to the owning module
and records that it passed as an OCSF API Activity event. The owning module
records what it did. The console shows a command only as declared, and never assigns a
tier itself.

| Field | Required | Meaning |
|---|---|---|
| `tier` | yes | `safe`: runs at once. `confirm`: a dialog first, with the preview when there is one. `typed`: the user types the value of `confirm_param`. `cli`: the console shows the command to copy, and the gateway never runs it |
| `argv` or `route` | exactly one | `argv`: an array run without a shell, by batch tools and daemons alike. `route`: daemons only, `{method, path}`, `POST`, `PUT` or `DELETE`, relative to `base_url` |
| `params` | when used | Each placeholder's `pattern` (a regular expression the whole value must match) and an optional `description` |
| `preview` | no | A read-only dry run, in the same form as the target: `{argv}` or `{route}` |
| `inverse` | no | The name of the command that undoes this one, offered as Undo |
| `confirm_param` | for `typed` | The param whose value the user types |
| `description` | no | One line for the console |
| `title` | no | The console's button label, at most 40 characters and no control characters; without it the console shows the command's name |
| `body` | no | `"json"`: the call carries a JSON object for the module (below). Only on a `POST` or `PUT` `route`, and never with `inverse` |

Rules the schema cannot check, which the gateway enforces when it loads a manifest (a
manifest that breaks one is refused):
- A placeholder `{name}` is a whole argv element or a whole path segment, never part of
  one. Every placeholder is declared in `params`, every declared param is used, and every
  param is required in a call.
- Patterns are anchored: the whole value must match. A value that could be read as an
  option (a leading `-`), or that holds control characters, needs a pattern that
  excludes it.
- `confirm_param` names a declared param. `inverse` names another command in the same
  catalogue, whose params are a subset of this command's. `preview` has the same form
  as the target (`argv` with `argv`, `route` with `route`) and uses only declared params.
- A `cli` command has `argv`, so the console has something to show. `purge`, and
  anything that needs `sudo`, is `cli`.
- A batch tool's command has `argv`. A daemon's command has a `route` when the daemon's
  own API does the work, and `argv` when a CLI does it outside the daemon, such as a
  decision written to the user's own file.
- Undo sends no body: an `inverse` names a command without `body`, and a command with
  `body` declares no `inverse` (the schema checks this side).

Undo calls the `inverse` with the params it declares, taken by name from the original
call; the others are dropped.

A command with `body = "json"` takes a JSON object besides its params, for text that a
path segment cannot carry, such as a note. The gateway checks only that the body
is a JSON object of at most 256 KiB, sends it to the route unchanged as
`application/json`, and records only its size in the audit log, never its content. The
module's OpenAPI types the body, and the module checks it. A `preview` of such a command
gets the same body, so its route takes it too.

Examples: `allow` and `unallow` in
[`manifest-secret-hygiene.toml`](fixtures/manifest-secret-hygiene.toml), the sniffer's
alert decisions in [`manifest-sniffer.toml`](fixtures/manifest-sniffer.toml), `cli` in
[`manifest-mop.toml`](fixtures/manifest-mop.toml), and a body and a title in
[`manifest-lifelog-notes.toml`](fixtures/manifest-lifelog-notes.toml).

## Attention items and runs

Two read shapes for the console. A module offers either one only if it wants
to; its own `findings` and `runs` documents keep their shapes.

**Attention items.** An `attention` read command (batch tools) or `GET /attention`
(daemons) returns a [page](#errors-and-lists) of items. Schema:
[`attention.schema.json`](schemas/attention.schema.json).
- Required fields:
  - `uid`: stable within the module;
  - `title`: short, with no secrets or payloads;
  - `module`: the writing module's repository name.
- Optional fields:
  - `severity_id`: OCSF. Without it, the item is "review", unranked, because severity
    comes only from the module.
  - `status_id`: OCSF Detection Finding.
  - `first_seen`, `last_seen`: contract UTC times.
  - `count`.
  - `entities`: `{kind, id, label?}` for links. `kind` is a word such as:
    - `process`: a `process.uid`;
    - `event`: a `metadata.uid`;
    - `session`: an agent session, by the id its agent gives it (agent-guard's
      `session_id`); never a kernel session;
    - `kernel_session`: a kernel session, its `process.session.uid` as the sniffer
      writes it;
    - `finding`: another module's item, as `<module>/<uid>` (its repository name, then
      its `uid`), such as the hub's incident members; the schema checks this form;
    - `file`, `package` or `host`.
- Other fields may follow.
- Examples: [`attention-sniffer.json`](fixtures/attention-sniffer.json),
  [`attention-pkg-guard.json`](fixtures/attention-pkg-guard.json),
  [`attention-hub.json`](fixtures/attention-hub.json).

**Runs.** A batch tool's `runs` read command prints `{module, runs}`. Schema:
[`runs.schema.json`](schemas/runs.schema.json).
- Each run has:
  - `id`;
  - `started` (UTC, or `null` before it starts);
  - `finished` (UTC, or `null` while it runs);
  - `outcome`: as in `last_run`, `running`, `succeeded`, `failed`, `waiting` or
    `cancelled`;
  - optionally `cost_usd` (`null` when unknown) and `record`.
- Every other field is the module's own, documented in its own schema.
- Examples: `runs-*.json` in [`fixtures/`](fixtures), one per module that has runs today.

## Live streams

A daemon with a live stream serves it as a WebSocket at `<base_url>/stream` and
declares it with `stream_url`.
- The client may pass `after`, a cursor the stream sent earlier. Without it, the stream
  starts at the newest data. A cursor the stream did not send is a 400.
- Each text message is one JSON object with a non-empty string `cursor`, which clients
  treat as opaque and pass back unchanged. Every other field is the module's own,
  documented in its OpenAPI document.
- The module paces its frames. An empty frame may serve as a heartbeat.
- The gateway serves each stream as server-sent events at `/m/{module}/stream`, one event
  per frame with the `cursor` as the event id. Until it reads `stream_url`,
  it assumes `<base_url>/stream` for every daemon.

## MCP

The gateway serves every module's described reads as read-only MCP tools, so a module
needs no MCP code of its own.

**Tools from reads.** The gateway builds a tool from each read a module describes:
- **A read command** with a `description` ([Batch tools](#batch-tools)) is the tool
  `<code>.<name>`, with `-` in the name written `_` (`sec.findings`). It takes no
  arguments: its input schema is an empty object.
- **A daemon's `GET` operation** in its OpenAPI document (`openapi_url`) is the tool
  `<code>.<operationId>` when the manifest lists its `operationId` in `mcp_operations`
  and the operation has a `description` or a `summary`, which becomes the tool's
  description. An operation not listed is never a tool, whatever its document says: a
  generator writes an `operationId` and a summary for every route. A listed id matches
  `^[a-z][a-z0-9_]*$`; a generator's default id changes when its route or function is
  renamed, so a daemon sets the id explicitly on each operation it lists. Its arguments are
  the operation's path and query parameters, each with its schema and description; path
  parameters are required, and query parameters as the operation says. The contract's
  own endpoints (`/healthz`, `/status`, `/metrics`, `/openapi.json`) and the live stream
  are never tools. A listed `operationId` that the document lacks, that names an
  operation other than `GET`, one of those endpoints or the stream, or whose operation
  has no description or summary, is left out and logged.
- `<code>` is the manifest's `code` in lower case. A tool's name is unique: the gateway
  keeps read commands first, then `GET` operations, then the module's own server, and
  logs and drops a later duplicate. The gateway's own tools are `gw.*`.
- **A call** runs the read as `/m/{module}/read/{name}` or `/m/{module}/api/{path}` do.
  The result is the read's JSON document. A failed read, or a module's 4xx or 5xx, is a
  tool error carrying the contract's `error` text. A page read takes `cursor` and `limit`
  as declared, and the client walks the pages.

**Opt-in.** A read command without a description is not a tool, and neither is a `GET`
operation that the manifest does not list. A tool's result goes to the MCP
client and, through it, to whatever model the client runs, which may be off the host. A
module describes a read command, or lists a `GET` operation, only when its output may go
there: secrets redacted in code and no captured payloads, as for any off-host call.
For a `GET` operation the list is that gate, not its description, which a generator
writes anyway. The description says what the read returns and when to use it.

**A module's own server.** A module writes its own MCP server, with the official SDK for
its language, only for tools its reads cannot express (the sniffer's query tools),
and declares it with `mcp_url` (Streamable HTTP). Its tools are named `<code>.<verb>`
(`sniff.query_events`) and only read. The gateway lists and calls them under the same
names.

**Nothing changes anything.** Every tool only reads: commands never become tools. Tools
that change anything exist only in CTL (safe commands under its policy).

## Conformance

A module conforms to 0.1 when:
1. its event fixtures validate against the OCSF schema exports it uses;
2. its `status` (or `status --json`), `healthz` and manifest fixtures validate against
   the schemas in `schemas/`, and a live response does too;
3. `/metrics` exposes the required metrics;
4. a daemon's error and list bodies validate against `error.schema.json` and
   `page.schema.json`;
5. its finding fixtures validate against `finding.schema.json` as well as their OCSF
   export, so a finding without a rule key fails, and a module that writes findings
   serves its per-rule counts.

Each module records its own conformance in its tests and evidence. The fixtures in
`fixtures/` show valid documents; `go test ./contract/` validates each one against its
schema.

## Shared data

Data more than one module reads, kept here so no module copies it. Using it is
optional, like the code.
- [`rules/`](rules/README.md): redaction rules for secrets in command lines and text
  (ours and gitleaks', MIT), with `cases.json`, the cases every loader must pass
  Loaders: Go `go/redact`, Rust `redact` in `rust/`.
- [`ids/process-uid.json`](ids/process-uid.json): `process.uid`, the identity of one
  process instance, is the UUIDv5 of `<boot_id>:<pid>:<start_ticks>` (the kernel's
  `boot_id`, the pid, and the start time in clock ticks since boot, `/proc/<pid>/stat`
  field 22) in the namespace the file names, with the cases every implementation passes
  Code: Go `go/id.ProcessUID`, Rust `id::process_uid` in `rust/`.
- [`ocsf/`](ocsf): OCSF 1.9.0 class exports for classes that two writers share, with
  profiles `datetime` and `host`. Today `detection_finding.schema.json` (2004), used by
  the Go types in `go/ocsf` and validated against
  `fixtures/ocsf-detection-finding-*.json`. A class with one writer keeps its export in
  that module.

These files are not part of `contract_version`: a rules update changes what is
redacted, not a shape. Each core release notes rule changes in
[CHANGELOG.md](../CHANGELOG.md).
