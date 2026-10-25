# Redaction rules

Rule data for secret redaction, shared by every module that redacts command lines or
text before it is stored off-line or leaves the machine. Each language loads the
same files: Go through `go/redact`, Rust through the crate in `rust/` (`redact`).

| File | What |
|---|---|
| `sniff.toml` | Our rules for secrets in command lines, URLs and headers, in gitleaks rule format. Moved from traffic-sniffer's `sniff-core/rules/` |
| `gitleaks.toml` | The gitleaks v8.30.1 default rule set, unchanged ([MIT](LICENSE-gitleaks)) |
| `cases.json` | Synthetic redaction cases every loader must pass |

Loading rules (the same in every language):
- `sniff.toml` loads first, then `gitleaks.toml`; on a tie the first-loaded rule names
  the span. Rules with a `path` are skipped: command lines have no file.
- A rule runs only when one of its keywords occurs (ASCII case ignored), or it has none.
- The secret is the rule's `secretGroup`, else the first non-empty group, else the whole
  match; an `entropy` threshold and the rule's and the global allowlists apply as in
  gitleaks.
- Each secret becomes `[REDACTED:<rule-id>]`; overlapping spans merge.
- Patterns are Go (RE2) syntax: `\w`, `\d`, `\s`, `\b` and their negations are ASCII
  only, so a letter such as `é` next to a secret is not part of it (`.` and negated
  brackets still match any character). A loader whose engine reads them as Unicode
  translates them to the ASCII sets, as the Rust loader does; `cases.json` checks it.

`cases.json` holds templates, not secrets: `{name}` placeholders are filled at test time
from the generator named in `fill`, so no secret-looking string is committed. In
`redacted`, `[R]` stands for any `[REDACTED:<id>]` marker. `unchanged` lists command
lines that must come back as they were.

Updating gitleaks: replace `gitleaks.toml` with the release's `config/gitleaks.toml`,
then fix the rule count in both loaders' tests so every change is seen.
