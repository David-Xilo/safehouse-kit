//! The contract's JSON Schemas (`contract/schemas/`) and the shared OCSF exports
//! (`contract/ocsf/`), embedded, and validation against them. Validators compile once, on
//! first use.

use std::sync::OnceLock;

use serde_json::Value;

/// One schema of the contract, or a shared OCSF class export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Schema {
    Status,
    BatchStatus,
    Healthz,
    Manifest,
    Error,
    Page,
    /// An attention read command's page.
    Attention,
    /// A runs read command's document.
    Runs,
    /// OCSF 1.9.0 Detection Finding (2004), profiles `datetime` and `host`, shared by
    /// every writer of 2004.
    OcsfDetectionFinding,
}

const COUNT: usize = Schema::OcsfDetectionFinding as usize + 1;

impl Schema {
    fn text(self) -> &'static str {
        match self {
            Schema::Status => include_str!("../../contract/schemas/status.schema.json"),
            Schema::BatchStatus => {
                include_str!("../../contract/schemas/batch-status.schema.json")
            }
            Schema::Healthz => include_str!("../../contract/schemas/healthz.schema.json"),
            Schema::Manifest => include_str!("../../contract/schemas/manifest.schema.json"),
            Schema::Error => include_str!("../../contract/schemas/error.schema.json"),
            Schema::Page => include_str!("../../contract/schemas/page.schema.json"),
            Schema::Attention => include_str!("../../contract/schemas/attention.schema.json"),
            Schema::Runs => include_str!("../../contract/schemas/runs.schema.json"),
            Schema::OcsfDetectionFinding => {
                include_str!("../../contract/ocsf/detection_finding.schema.json")
            }
        }
    }

    fn validator(self) -> &'static jsonschema::Validator {
        static VALIDATORS: [OnceLock<jsonschema::Validator>; COUNT] =
            [const { OnceLock::new() }; COUNT];
        VALIDATORS[self as usize].get_or_init(|| {
            let schema: Value = serde_json::from_str(self.text()).expect("contract schema is JSON");
            jsonschema::validator_for(&schema).expect("contract schema compiles")
        })
    }
}

/// Every error of `doc` against `schema`, each as "path: message" (path `/` for the root).
pub fn errors(schema: Schema, doc: &Value) -> Vec<String> {
    schema.validator().iter_errors(doc).map(describe).collect()
}

/// The first error of `doc` against `schema`, or `None` when it is valid.
pub fn check(schema: Schema, doc: &Value) -> Option<String> {
    schema.validator().iter_errors(doc).next().map(describe)
}

fn describe(e: jsonschema::ValidationError<'_>) -> String {
    let path = e.instance_path().to_string();
    let path = if path.is_empty() { "/" } else { &path };
    format!("{path}: {e}")
}
