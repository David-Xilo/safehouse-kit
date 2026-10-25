//! The redactor's fixed cost: loading every rule stays small, whatever the input. In a
//! test binary of its own, so no other test's memory counts.
#![cfg(target_os = "linux")]

use safehouse_core::redact::Redactor;

/// Resident memory in bytes, from `/proc/self/smaps_rollup` (in kB, whatever the page size).
fn resident() -> usize {
    let rollup = std::fs::read_to_string("/proc/self/smaps_rollup").unwrap();
    let line = rollup.lines().find(|l| l.starts_with("Rss:")).unwrap();
    let kib: usize = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    kib << 10
}

#[test]
fn loading_the_rules_costs_little_memory() {
    let before = resident();
    let redactor = Redactor::load().unwrap();
    let fake = "export GITHUB_TOKEN=ghp_0123456789abcdefghijABCDEFGHIJ012345"; // gitleaks:allow trufflehog:ignore
    let redacted = redactor.text(fake);
    assert!(redacted.contains("[REDACTED:"));
    let grown = resident().saturating_sub(before);
    assert!(grown < 32 << 20, "the loaded rules use {} MiB", grown >> 20);
}
