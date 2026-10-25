//! Event and process identities.

use uuid::Uuid;

/// Namespace for [`process_uid`]. Changing it breaks joins with stored events.
const PROCESS_UID_NAMESPACE: Uuid = Uuid::from_u128(0x85b5_6229_910c_4309_8415_ad67_a910_7337);

/// A new time-sortable event identity (UUIDv7).
pub fn new_event_uid() -> String {
    Uuid::now_v7().to_string()
}

/// Stable identity of one process instance: pids are reused, so the boot and the start
/// time (clock ticks since boot, `/proc/<pid>/stat` field 22) disambiguate. Host capture,
/// network attribution and correlation all derive the same value, and so does Go's
/// `go/id.ProcessUID`: both pass `contract/ids/process-uid.json`.
pub fn process_uid(boot_id: &str, pid: u32, start_ticks: u64) -> String {
    let name = format!("{boot_id}:{pid}:{start_ticks}");
    Uuid::new_v5(&PROCESS_UID_NAMESPACE, name.as_bytes()).to_string()
}
