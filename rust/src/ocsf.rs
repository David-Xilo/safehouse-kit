//! OCSF 1.9.0 envelope and the objects every class shares (contract "Events").
//!
//! Field order in each struct is the serialization order, and golden fixtures depend on it.
//! Only fields a caller needs are modeled; decoding ignores unknown fields. Class types
//! stay in the module that writes them; the checks here are the ones every class shares.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF schema version the types conform to.
pub const OCSF_VERSION: &str = "1.9.0";

/// OCSF `device.type_id` values used here.
pub mod device_type {
    pub const UNKNOWN: u8 = 0;
}

/// OCSF `file.type_id` values used here.
pub mod file_type {
    pub const REGULAR: u8 = 1;
}

#[derive(Debug, thiserror::Error)]
pub enum EventError {
    #[error("cannot decode event: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("missing or non-integer class_uid")]
    MissingClassUid,
    #[error("unsupported class_uid {0}")]
    UnsupportedClass(u64),
    #[error("inconsistent event: {0}")]
    Inconsistent(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[repr(u8)]
pub enum SeverityId {
    Unknown = 0,
    Informational = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
    Fatal = 6,
    Other = 99,
}

impl SeverityId {
    /// A short word for terminals.
    pub fn label(self) -> &'static str {
        match self {
            SeverityId::Unknown => "unknown",
            SeverityId::Informational => "info",
            SeverityId::Low => "low",
            SeverityId::Medium => "medium",
            SeverityId::High => "high",
            SeverityId::Critical => "critical",
            SeverityId::Fatal => "fatal",
            SeverityId::Other => "other",
        }
    }
}

/// OCSF `type_uid = class_uid * 100 + activity_id`.
pub fn type_uid(class_uid: u32, activity_id: u32) -> u32 {
    class_uid * 100 + activity_id
}

pub fn inconsistent(why: &str) -> Result<(), EventError> {
    Err(EventError::Inconsistent(why.to_owned()))
}

/// Checks shared by every class: `type_uid`, `time` against `time_dt`, and OCSF's
/// "device needs hostname or uid".
pub fn check_header(
    class_uid: u32,
    activity_id: u32,
    type_uid_value: u32,
    time: i64,
    time_dt: DateTime<Utc>,
    device: &Device,
) -> Result<(), EventError> {
    if type_uid_value != type_uid(class_uid, activity_id) {
        return inconsistent("type_uid does not match class and activity");
    }
    if time != time_dt.timestamp_millis() {
        return inconsistent("time does not match time_dt");
    }
    if device.hostname.is_none() && device.uid.is_none() {
        return inconsistent("device needs hostname or uid");
    }
    Ok(())
}

/// OCSF: an actor needs a process or a user.
pub fn check_actor(actor: &Actor) -> Result<(), EventError> {
    if actor.process.is_none() && actor.user.is_none() {
        return inconsistent("actor needs process or user");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Metadata {
    /// Event identity, a UUIDv7.
    pub uid: String,
    pub version: String,
    pub product: Product,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<String>,
}

impl Metadata {
    /// Metadata for an event the module `product` writes now, with the OCSF profiles it
    /// declares (contract: `datetime` and `host`, plus `linux` when used).
    pub fn new(uid: String, product: Product, profiles: &[&str]) -> Self {
        Self {
            uid,
            version: OCSF_VERSION.to_owned(),
            product,
            profiles: profiles.iter().map(|p| (*p).to_owned()).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Product {
    pub name: String,
    pub vendor_name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Device {
    /// See [`device_type`].
    pub type_id: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Stable host identity, e.g. `/etc/machine-id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// Kernel boot identity, `/proc/sys/kernel/random/boot_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_uid: Option<String>,
}

impl Device {
    /// This machine: host name, machine id and boot id. For a pcap file recorded
    /// elsewhere this is still the replaying host.
    pub fn this_host() -> Self {
        let read = |path: &str| {
            std::fs::read_to_string(path)
                .ok()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
        };
        Device {
            type_id: device_type::UNKNOWN,
            hostname: Some(
                rustix::system::uname()
                    .nodename()
                    .to_string_lossy()
                    .into_owned(),
            ),
            uid: read("/etc/machine-id"),
            boot_uid: read("/proc/sys/kernel/random/boot_id"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Actor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<Process>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Process {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Stable process identity from [`crate::process_uid`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd_line: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<File>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_time_dt: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminated_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminated_time_dt: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    // The schema refers to itself here instead of expanding forever.
    #[cfg_attr(feature = "openapi", schema(no_recursion))]
    pub parent_process: Option<Box<Process>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<Session>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct File {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// See [`file_type`].
    pub type_id: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct User {
    /// Numeric uid as a string, as OCSF defines it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Session {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<String>,
}
