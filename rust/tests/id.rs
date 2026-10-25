//! The shared `process_uid` cases (`contract/ids/process-uid.json`), which Go's
//! `go/id.ProcessUID` passes too.

use safehouse_core::id::process_uid;
use serde::Deserialize;

#[derive(Deserialize)]
struct Cases {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    boot_id: String,
    pid: u32,
    start_ticks: u64,
    uid: String,
}

#[test]
fn process_uid_passes_the_shared_cases() {
    let file: Cases =
        serde_json::from_str(include_str!("../../contract/ids/process-uid.json")).unwrap();
    assert!(file.cases.len() >= 5, "read {} cases", file.cases.len());
    for c in &file.cases {
        assert_eq!(
            process_uid(&c.boot_id, c.pid, c.start_ticks),
            c.uid,
            "{}:{}:{}",
            c.boot_id,
            c.pid,
            c.start_ticks
        );
    }
}
