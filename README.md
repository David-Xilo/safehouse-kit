# safehouse-kit

The shared kit of safehouse, a set of small programs that watch one Linux machine: sensors
record what happens (processes, network, files, packages, secrets), a hub turns their
findings into incidents, and a gateway serves every module to one local console. The kit
holds what those modules share, for every language:

- the **module contract**: the event envelope, `status`, `healthz`, batch status, the
  manifest with its commands, attention items, runs, live streams and MCP tools, and the
  rule key and labels every finding carries, with
  JSON Schemas and synthetic golden fixtures, in [`contract/`](contract/README.md);
- small **Go** and **Rust** packages for the code that modules would otherwise copy.

Using the packages is optional. A module in any language meets the contract through
files, HTTP and schemas, and proves it against the fixtures here.

Current tag: `v0.10.1`. Contract version: `0.1`.

## What is here

| Path | What |
|---|---|
| `contract/` | Contract README, `schemas/`, `fixtures/`; `rules/` (redaction rules, ours and gitleaks', with `cases.json`); `ocsf/` (OCSF 1.9.0 exports); `ids/` (`process-uid.json` cases) |
| `contract` (Go) | `Version` and the embedded schemas and fixtures |
| `go/ocsf` | OCSF envelope (`Product`, `Metadata`, `Device`, `NewUID`), Detection Finding 2004 with its rule key (`Analytic`), and the label words |
| `go/batch`, `go/utc` | Batch status types and per-rule counts (`RuleTally`); RFC 3339 UTC time |
| `go/redact` | Redaction over `contract/rules/` (`Load`, `Text`, `IDs`) |
| `go/schematest` | Schema checks for tests |
| `go/jev` | A client for TypeSafe's Jev (Noul, Score and Choice questions) with retries and an HTTP/2 ping |
| `go/id` | `ProcessUID`, the same formula as Rust's `id::process_uid` |
| `rust/` | Crate `safehouse-core`: `id`, `ocsf`, `jsonl`, `status`; features below |

Rust features: `openapi` (utoipa `ToSchema` on the envelope and status types), `redact`
(`redact::Redactor` over `contract/rules/`), `schema` (`schema::check` against
`contract/schemas/`), `local-model` (`local::Client`: one schema-checked chat with a
model on Ollama at a loopback address, pinned by digest in `rust/local-tiers.toml`),
`write-token` (`token::WriteToken`: loads the local write token from a file only its
owner can read, checks a write's `Authorization: Bearer` header in constant time, and
signs and checks the console's HttpOnly, SameSite=Strict session cookie with it).

## Using it from Go

Go 1.27 or later. `go get` takes the newest tag; `go.mod` then pins it.

```sh
go get github.com/David-Xilo/safehouse-kit@latest
```

```go
import (
	"github.com/David-Xilo/safehouse-kit/go/ocsf"
	"github.com/David-Xilo/safehouse-kit/go/redact"
)
```

A private fork needs Go to skip the public proxy and checksum server, and git to reach
GitHub with a credential:

```sh
go env -w 'GOPRIVATE=github.com/<owner>/*'   # quoted: zsh expands a bare *
gh auth setup-git
```

## Using it from Rust

Rust 1.98 or later. The crate is a git dependency pinned by tag, not on crates.io: it
reads `contract/` from the same checkout, which a crates.io package would not hold. The
package is named `safehouse-core`.

```toml
[dependencies]
safehouse-core = { git = "https://github.com/David-Xilo/safehouse-kit", tag = "v0.10.1", features = ["redact"] }
```

```rust
let redactor = safehouse_core::redact::Redactor::load()?;
let clean = redactor.text("curl -H 'Authorization: Bearer x' https://example.org/");
```

A private fork over SSH needs cargo to fetch with the git CLI: commit
`.cargo/config.toml` with `[net] git-fetch-with-cli = true` in the user crate.

## Releases

One tag `vX.Y.Z` releases the Go module, the Rust crate and the contract together. A
change is tagged as the next minor once merged, or the next patch when the API is
unchanged. `contract_version` changes only when the contract does: a breaking change
raises it and lists what each module must change. [CHANGELOG.md](CHANGELOG.md) has one
line per tag.

## What it does at run time

Nothing of its own: the kit is a library that installs nothing and runs nothing. What a
caller does with it leaves the host only through that caller: `go/jev` posts to the Jev
base URL the caller gives, with the key the caller gives, and the local-model client
talks only to Ollama on a loopback address. The packages never read or log a key, except
the write token, which `token::WriteToken` reads from the file the caller names and never
prints.

## Checks

```sh
gofmt -l .        # prints nothing
go vet ./...
go test -race ./...
(cd rust && cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-features)
```

The tests need no network and no key: `go/jev` and the local-model client run against
fake servers. One Rust test that calls a real Ollama on the host is ignored by default.

## Licence

Copyright 2026 The safehouse authors. Licensed under the Apache License, Version 2.0:
see [LICENSE](LICENSE). `contract/rules/gitleaks.toml` is the gitleaks default rule set
under the MIT licence: see [contract/rules/LICENSE-gitleaks](contract/rules/LICENSE-gitleaks).
