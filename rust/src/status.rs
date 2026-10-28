//! Contract status shapes: a daemon's `GET /status` and a batch tool's `status --json`
//! (`contract/schemas/status.schema.json`, `batch-status.schema.json`). Unknown values
//! are null, never 0. Times are RFC 3339 in UTC with a `Z` suffix.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ocsf::SeverityId;

/// The contract version every status, batch status and manifest carries.
pub const CONTRACT_VERSION: &str = "0.1";

/// `GET /status` of a daemon. Unknown values are null, never 0.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct DaemonStatus {
    pub contract_version: String,
    pub module: String,
    pub version: String,
    pub state: DaemonState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub since: String,
    pub last_event_time: Option<String>,
    pub counts: BTreeMap<String, Option<u64>>,
    pub drops: Option<u64>,
    pub queue_depth: Option<u64>,
    pub store: StoreStatus,
    pub ai: Ai,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum DaemonState {
    Starting,
    Ok,
    Degraded,
    Down,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct StoreStatus {
    pub bytes: Option<u64>,
    pub events: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct Ai {
    pub mode: AiMode,
    pub provider_state: Option<ProviderState>,
    pub budget: Option<Budget>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum AiMode {
    Jev,
    Local,
    Off,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum ProviderState {
    Ok,
    Degraded,
    Down,
    Unused,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub used: Option<f64>,
    pub cap: Option<f64>,
    /// `calls`, `tokens` or `usd`.
    pub unit: String,
    /// `minute`, `day` or `run`.
    pub window: String,
}

/// `status --json` of a batch tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct BatchStatus {
    pub contract_version: String,
    pub module: String,
    pub version: String,
    pub state: BatchState,
    pub last_run: Option<LastRun>,
    pub waiting: Vec<Waiting>,
    /// Printed by a tool that writes findings, empty when it holds none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_counts: Option<Vec<RuleCount>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum BatchState {
    Idle,
    Running,
    Waiting,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct LastRun {
    pub id: String,
    pub started: String,
    pub finished: Option<String>,
    /// `succeeded`, `failed`, `waiting`, `cancelled` or `running`.
    pub outcome: String,
    pub cost_usd: Option<f64>,
    /// Path of the last-run record on disk.
    pub record: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct Waiting {
    pub what: String,
    pub why: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

/// The label column of findings that have no label.
pub const LABEL_NONE: &str = "none";

/// One row of per-rule counts: the findings of one rule first raised on one UTC day, at
/// one severity, that carry one label now. A batch tool prints them as `rule_counts`; a
/// daemon serves them in `/metrics` with [`rule_findings_metric`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RuleCount {
    /// The rule key, `finding_info.analytic.uid`.
    pub rule: String,
    /// `YYYY-MM-DD`, UTC.
    pub day: String,
    /// When the finding was raised.
    pub severity_id: SeverityId,
    /// One of [`crate::ocsf::label`], or [`LABEL_NONE`].
    pub label: String,
    pub count: u64,
}

/// The `<prefix>_rule_findings` gauge in Prometheus text, one sample per row. With no
/// rows it is declared with no sample.
pub fn rule_findings_metric(prefix: &str, rows: &[RuleCount]) -> String {
    let mut out = format!(
        "# HELP {prefix}_rule_findings Findings by rule key, UTC day first raised, severity at creation and current label.\n\
         # TYPE {prefix}_rule_findings gauge\n"
    );
    for r in rows {
        out.push_str(&format!(
            "{prefix}_rule_findings{{rule=\"{}\",day=\"{}\",severity_id=\"{}\",label=\"{}\"}} {}\n",
            escape(&r.rule),
            escape(&r.day),
            r.severity_id as u8,
            escape(&r.label),
            r.count,
        ));
    }
    out
}

/// A Prometheus label value: backslash, double quote and line feed escaped.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
