//! The shared redaction cases (`contract/rules/cases.json`), which the Go loader runs
//! too. Secrets are generated here, so none is committed.

use std::collections::BTreeMap;

use safehouse_core::redact::{Redactor, ids};
use serde::Deserialize;

#[derive(Deserialize)]
struct Cases {
    rule_count: usize,
    fill: BTreeMap<String, Fill>,
    redacted: Vec<(String, String)>,
    exact: Vec<(String, String)>,
    unchanged: Vec<String>,
}

#[derive(Deserialize)]
struct Fill {
    #[serde(default)]
    prefix: String,
    alphabet: String,
    length: usize,
}

const ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// A fixed-seed xorshift: the same secrets on every run, without a rand dependency.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n as u64) as usize
    }
}

/// Replaces each `[REDACTED:<id>]` marker with `[R]`.
fn mask(text: &str) -> String {
    let marker = regex::Regex::new(r"\[REDACTED:[^\]]*\]").unwrap();
    marker.replace_all(text, "[R]").into_owned()
}

#[test]
fn shared_cases() {
    let cases: Cases =
        serde_json::from_str(include_str!("../../contract/rules/cases.json")).unwrap();
    let redactor = Redactor::load().unwrap();
    assert_eq!(redactor.rule_count(), cases.rule_count);

    let mut rng = Rng(0x5eed_1234_abcd_0001);
    let fills: Vec<(String, String)> = cases
        .fill
        .iter()
        .map(|(name, f)| {
            let alphabet = if f.alphabet == "alnum" {
                ALNUM
            } else {
                &f.alphabet
            };
            let alphabet = alphabet.as_bytes();
            let mut value = f.prefix.clone();
            for _ in 0..f.length {
                value.push(alphabet[rng.below(alphabet.len())] as char);
            }
            (format!("{{{name}}}"), value)
        })
        .collect();

    for (template, want) in &cases.redacted {
        let input = fills
            .iter()
            .fold(template.clone(), |s, (k, v)| s.replace(k, v));
        assert_eq!(&mask(&redactor.text(&input)), want, "{template}");
    }
    for (input, want) in &cases.exact {
        assert_eq!(redactor.text(input), want.as_str());
    }
    for input in &cases.unchanged {
        assert_eq!(
            redactor.text(input),
            input.as_str(),
            "changed an ordinary line"
        );
    }
}

#[test]
fn ids_are_the_command_line_rules() {
    let ids = ids().unwrap();
    assert_eq!(ids.len(), 8);
    assert_eq!(ids[0], "argv-secret-flag");
}
