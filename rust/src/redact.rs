//! Secret redaction in text, over the shared rules in `contract/rules/`.
//!
//! Rules come from the gitleaks rule set (`gitleaks.toml`, MIT) plus our command-line
//! rules in the same format (`sniff.toml`). The loader reproduces gitleaks' matching
//! semantics: keyword prefilter, secret group, entropy threshold and allowlists, as
//! `contract/rules/README.md` states and `cases.json` checks in every language.

use std::borrow::Cow;
use std::ops::Range;

use aho_corasick::AhoCorasick;
use regex::{Captures, Match, Regex, RegexBuilder};
use serde::Deserialize;

const GITLEAKS_RULES: &str = include_str!("../../contract/rules/gitleaks.toml");
const SNIFF_RULES: &str = include_str!("../../contract/rules/sniff.toml");

/// Compiled size limit per regex, above the crate's 10 MiB default: headroom so that a
/// large rule in a gitleaks update still loads (Go takes it). The memory test bounds the
/// whole load.
const REGEX_SIZE_LIMIT: usize = 64 << 20;

#[derive(Debug, thiserror::Error)]
pub enum RedactError {
    #[error("{file}: {source}")]
    Parse {
        file: &'static str,
        source: toml::de::Error,
    },
    #[error("rule {rule}: {source}")]
    Regex { rule: String, source: regex::Error },
    #[error("keyword prefilter: {0}")]
    Keywords(#[from] aho_corasick::BuildError),
}

pub struct Redactor {
    rules: Vec<Rule>,
    global_allowlists: Vec<Allowlist>,
    /// Keyword prefilter; pattern `i` belongs to rule `keyword_rule[i]`.
    keywords: AhoCorasick,
    keyword_rule: Vec<usize>,
}

impl Redactor {
    /// Loads the embedded rule sets. Our command-line rules come first, so their ids win
    /// when a gitleaks rule finds the same span. Rules on file paths are skipped: command
    /// lines and events have no file to match.
    pub fn load() -> Result<Self, RedactError> {
        let sniff = parse("rules/sniff.toml", SNIFF_RULES)?;
        let gitleaks = parse("rules/gitleaks.toml", GITLEAKS_RULES)?;

        let mut rules = Vec::new();
        for def in sniff.rules.into_iter().chain(gitleaks.rules) {
            let Some(pattern) = def.regex.as_deref().filter(|_| def.path.is_none()) else {
                continue;
            };
            let regex = compile(pattern).map_err(|source| RedactError::Regex {
                rule: def.id.clone(),
                source,
            })?;
            rules.push(Rule::new(def, regex)?);
        }

        let global_allowlists = gitleaks
            .allowlist
            .into_iter()
            .chain(sniff.allowlist)
            .map(|def| Allowlist::new(def, "global allowlist"))
            .collect::<Result<_, _>>()?;

        let mut patterns = Vec::new();
        let mut keyword_rule = Vec::new();
        for (index, rule) in rules.iter().enumerate() {
            for keyword in &rule.keywords {
                patterns.push(keyword.as_str());
                keyword_rule.push(index);
            }
        }
        let keywords = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)?;

        Ok(Self {
            rules,
            global_allowlists,
            keywords,
            keyword_rule,
        })
    }

    /// Rules loaded; pinned by tests so a rules update shows every change.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Replaces every detected secret with `[REDACTED:<rule-id>]`; borrowed when nothing
    /// was found.
    pub fn text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let active = self.active_rules(text);
        let mut spans: Vec<(Range<usize>, usize)> = Vec::new();
        for (index, rule) in self.rules.iter().enumerate() {
            if !active[index] {
                continue;
            }
            for caps in rule.regex.captures_iter(text) {
                if let Some(range) = self.secret_range(rule, &caps, text) {
                    spans.push((range, index));
                }
            }
        }
        if spans.is_empty() {
            return Cow::Borrowed(text);
        }

        // Earliest start first; on a tie the longest span, then the first-loaded rule.
        spans.sort_by(|(a, ai), (b, bi)| {
            (a.start, std::cmp::Reverse(a.end), ai).cmp(&(b.start, std::cmp::Reverse(b.end), bi))
        });
        let mut merged: Vec<(Range<usize>, usize)> = Vec::new();
        for (range, index) in spans {
            match merged.last_mut() {
                Some((last, _)) if range.start < last.end => last.end = last.end.max(range.end),
                _ => merged.push((range, index)),
            }
        }

        let mut out = String::with_capacity(text.len());
        let mut cursor = 0;
        for (range, index) in merged {
            out.push_str(&text[cursor..range.start]);
            out.push_str("[REDACTED:");
            out.push_str(&self.rules[index].id);
            out.push(']');
            cursor = range.end;
        }
        out.push_str(&text[cursor..]);
        Cow::Owned(out)
    }

    /// gitleaks' prefilter: a rule runs only if one of its keywords occurs (ignoring
    /// ASCII case) or it has no keywords.
    fn active_rules(&self, text: &str) -> Vec<bool> {
        let mut active: Vec<bool> = self.rules.iter().map(|r| r.keywords.is_empty()).collect();
        for m in self.keywords.find_overlapping_iter(text) {
            active[self.keyword_rule[m.pattern().as_usize()]] = true;
        }
        active
    }

    /// gitleaks semantics: the configured secret group, else the first non-empty group,
    /// else the whole match. Empty secrets are ignored.
    fn secret_range(&self, rule: &Rule, caps: &Captures<'_>, text: &str) -> Option<Range<usize>> {
        let whole = caps.get(0)?;
        let secret = if rule.secret_group > 0 {
            caps.get(rule.secret_group)?
        } else {
            (1..caps.len())
                .filter_map(|g| caps.get(g))
                .find(|m| !m.as_str().is_empty())
                .unwrap_or(whole)
        };
        if secret.as_str().is_empty() {
            return None;
        }
        if let Some(threshold) = rule.entropy
            && shannon_entropy(secret.as_str()) <= threshold
        {
            return None;
        }
        let line = line_around(text, whole.range());
        let allowed = rule
            .allowlists
            .iter()
            .chain(&self.global_allowlists)
            .any(|a| a.allows(secret, whole, line));
        (!allowed).then(|| secret.range())
    }
}

struct Rule {
    id: String,
    regex: Regex,
    keywords: Vec<String>,
    entropy: Option<f64>,
    secret_group: usize,
    allowlists: Vec<Allowlist>,
}

impl Rule {
    fn new(def: RuleDef, regex: Regex) -> Result<Self, RedactError> {
        let allowlists = def
            .allowlists
            .into_iter()
            .map(|a| Allowlist::new(a, &def.id))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            // The keyword matcher ignores ASCII case, so keywords are kept as written.
            keywords: def.keywords,
            id: def.id,
            regex,
            entropy: def.entropy.filter(|e| *e > 0.0),
            secret_group: def.secret_group,
            allowlists,
        })
    }
}

#[derive(Clone, Copy)]
enum Target {
    Secret,
    Match,
    Line,
}

struct Allowlist {
    regexes: Vec<Regex>,
    target: Target,
    stopwords: Vec<String>,
    all_must_match: bool,
}

impl Allowlist {
    fn new(def: AllowlistDef, owner: &str) -> Result<Self, RedactError> {
        let regexes = def
            .regexes
            .iter()
            .map(|p| {
                compile(p).map_err(|source| RedactError::Regex {
                    rule: format!("{owner} allowlist"),
                    source,
                })
            })
            .collect::<Result<_, _>>()?;
        let target = match def.regex_target.as_deref() {
            Some("match") => Target::Match,
            Some("line") => Target::Line,
            _ => Target::Secret,
        };
        Ok(Self {
            regexes,
            target,
            stopwords: def.stopwords.iter().map(|w| w.to_lowercase()).collect(),
            all_must_match: def.condition.is_some_and(|c| c.eq_ignore_ascii_case("and")),
        })
    }

    fn allows(&self, secret: Match<'_>, whole: Match<'_>, line: &str) -> bool {
        if self.regexes.is_empty() && self.stopwords.is_empty() {
            return false;
        }
        let target = match self.target {
            Target::Secret => secret.as_str(),
            Target::Match => whole.as_str(),
            Target::Line => line,
        };
        let regex_hit = self.regexes.iter().any(|r| r.is_match(target));
        let lower = secret.as_str().to_lowercase();
        let stopword_hit = self.stopwords.iter().any(|w| lower.contains(w.as_str()));
        if self.all_must_match {
            (self.regexes.is_empty() || regex_hit) && (self.stopwords.is_empty() || stopword_hit)
        } else {
            regex_hit || stopword_hit
        }
    }
}

#[derive(Deserialize)]
struct RuleFile {
    #[serde(default)]
    allowlist: Option<AllowlistDef>,
    #[serde(default)]
    rules: Vec<RuleDef>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuleDef {
    id: String,
    regex: Option<String>,
    #[serde(default)]
    keywords: Vec<String>,
    entropy: Option<f64>,
    #[serde(default)]
    secret_group: usize,
    path: Option<String>,
    #[serde(default)]
    allowlists: Vec<AllowlistDef>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AllowlistDef {
    #[serde(default)]
    regexes: Vec<String>,
    regex_target: Option<String>,
    #[serde(default)]
    stopwords: Vec<String>,
    condition: Option<String>,
}

/// The ids of our command-line rules (`sniff.toml`), in file order.
pub fn ids() -> Result<Vec<String>, RedactError> {
    let sniff = parse("rules/sniff.toml", SNIFF_RULES)?;
    Ok(sniff.rules.into_iter().map(|r| r.id).collect())
}

fn parse(file: &'static str, text: &str) -> Result<RuleFile, RedactError> {
    toml::from_str(text).map_err(|source| RedactError::Parse { file, source })
}

fn compile(pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(&from_re2(pattern))
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
}

/// gitleaks patterns are Go (RE2) syntax. Two differences matter to the Rust `regex`
/// crate, so they are translated:
/// - a `{` that does not start a valid `{n}`, `{n,}` or `{n,m}` repetition is a literal
///   (e.g. `{{`, `${`); the crate rejects those, so they are escaped;
/// - `\w`, `\d`, `\s`, `\b` and their negations are ASCII-only in RE2 but Unicode in the
///   crate; they become the RE2 sets, which also keeps the compiled rules small
///   (about 16 MiB, against about 550 MiB with the Unicode sets).
///
/// Only one bracket level is tracked: inside a class, RE2 nests nothing but POSIX classes,
/// which are copied as they are.
///
/// Everything else is the same syntax.
fn from_re2(pattern: &str) -> Cow<'_, str> {
    let mut out = String::with_capacity(pattern.len() + 8);
    let mut changed = false;
    let mut in_class = false;
    let mut chars = pattern.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                let Some((_, escaped)) = chars.next() else {
                    out.push(c);
                    continue;
                };
                match ascii_perl_class(escaped, in_class) {
                    Some(set) => {
                        out.push_str(set);
                        changed = true;
                    }
                    None => {
                        out.push(c);
                        out.push(escaped);
                    }
                }
                continue;
            }
            '[' if !in_class => {
                in_class = true;
                out.push(c);
                // A `]` right after `[` or `[^` is a literal, not the end of the class.
                if let Some(&(_, '^')) = chars.peek() {
                    out.push('^');
                    chars.next();
                }
                if let Some(&(_, ']')) = chars.peek() {
                    out.push(']');
                    chars.next();
                }
                continue;
            }
            // A POSIX class such as `[:alnum:]` is the only bracket RE2 nests in a class.
            '[' if in_class && pattern[i + 1..].starts_with(':') => {
                if let Some(len) = pattern[i..].find(":]") {
                    let posix = &pattern[i..i + len + 2];
                    out.push_str(posix);
                    for _ in posix.chars().skip(1) {
                        chars.next();
                    }
                    continue;
                }
            }
            ']' if in_class => in_class = false,
            '{' if !in_class && !is_repetition(&pattern.as_bytes()[i + 1..]) => {
                out.push_str("\\{");
                changed = true;
                continue;
            }
            _ => {}
        }
        out.push(c);
    }
    if changed {
        Cow::Owned(out)
    } else {
        Cow::Borrowed(pattern)
    }
}

/// RE2's ASCII meaning of a Perl class escape `\<c>`. The sets are bracket classes, which
/// the crate also takes nested inside a class; word boundaries exist only outside one.
fn ascii_perl_class(c: char, in_class: bool) -> Option<&'static str> {
    Some(match c {
        'w' => "[0-9A-Za-z_]",
        'W' => "[^0-9A-Za-z_]",
        'd' => "[0-9]",
        'D' => "[^0-9]",
        's' => r"[\t\n\x0C\r ]",
        'S' => r"[^\t\n\x0C\r ]",
        'b' if !in_class => r"(?-u:\b)",
        'B' if !in_class => r"(?-u:\B)",
        _ => return None,
    })
}

/// Whether `rest` (the text after a `{`) is `n}`, `n,}` or `n,m}`.
fn is_repetition(rest: &[u8]) -> bool {
    let digits = |s: &[u8]| s.iter().take_while(|b| b.is_ascii_digit()).count();
    let n = digits(rest);
    if n == 0 {
        return false;
    }
    match rest.get(n) {
        Some(b'}') => true,
        Some(b',') => {
            let m = digits(&rest[n + 1..]);
            rest.get(n + 1 + m) == Some(&b'}')
        }
        _ => false,
    }
}

/// The line of `text` containing `range`.
fn line_around(text: &str, range: Range<usize>) -> &str {
    let start = text[..range.start].rfind('\n').map_or(0, |i| i + 1);
    let end = text[range.end..]
        .find('\n')
        .map_or(text.len(), |i| range.end + i);
    &text[start..end]
}

/// Shannon entropy as gitleaks computes it: character frequencies over the byte length.
fn shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in data.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let inv_len = 1.0 / data.len() as f64;
    counts
        .values()
        .map(|&n| {
            let p = n as f64 * inv_len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::from_re2;

    #[test]
    fn re2_syntax_becomes_the_crates() {
        let cases = [
            (r"\bkey\B", r"(?-u:\b)key(?-u:\B)"),
            (r"[\w.-]\d\S", r"[[0-9A-Za-z_].-][0-9][^\t\n\x0C\r ]"),
            (
                r"pat[[:alnum:]\w]{14}\b",
                r"pat[[:alnum:][0-9A-Za-z_]]{14}(?-u:\b)",
            ),
            (r"${x}{2}[{]", r"$\{x}{2}[{]"),
            (r"\\w", r"\\w"),
        ];
        for (re2, want) in cases {
            assert_eq!(from_re2(re2), want, "{re2}");
        }
    }
}
