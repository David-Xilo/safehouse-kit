//! Every golden fixture in `contract/fixtures/` matches its schema, and the status types
//! read and write the status fixtures unchanged. The Go tests check the same fixtures.

use std::path::Path;

use safehouse_core::ocsf::{Metadata, OCSF_VERSION, Product};
use safehouse_core::schema::{self, Schema};
use safehouse_core::status::{BatchStatus, DaemonStatus};
use serde_json::Value;

/// A fixture's file-name prefix and its schema; longer prefixes first.
const SCHEMA_FOR: [(&str, Schema); 9] = [
    ("batch-status-", Schema::BatchStatus),
    ("status-", Schema::Status),
    ("healthz-", Schema::Healthz),
    ("manifest-", Schema::Manifest),
    ("error-", Schema::Error),
    ("page-", Schema::Page),
    ("ocsf-detection-finding-", Schema::OcsfDetectionFinding),
    ("attention-", Schema::Attention),
    ("runs-", Schema::Runs),
];

fn contract_dir() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../contract"))
}

fn read_fixture(name: &str) -> Value {
    let text = std::fs::read_to_string(contract_dir().join("fixtures").join(name)).unwrap();
    if name.ends_with(".toml") {
        let doc: toml::Value = toml::from_str(&text).unwrap();
        serde_json::to_value(doc).unwrap()
    } else {
        serde_json::from_str(&text).unwrap()
    }
}

#[test]
fn every_fixture_matches_its_schema() {
    let mut checked = 0;
    for entry in std::fs::read_dir(contract_dir().join("fixtures")).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if name.ends_with(".txt") {
            continue; // Prometheus text has no JSON Schema
        }
        let Some((_, schema)) = SCHEMA_FOR.iter().find(|(p, _)| name.starts_with(p)) else {
            panic!("{name}: no schema for this fixture name");
        };
        let doc = read_fixture(&name);
        let errors = schema::errors(*schema, &doc);
        assert!(errors.is_empty(), "{name}: {errors:?}");
        checked += 1;
    }
    assert!(
        checked >= 20,
        "checked {checked} fixtures, want at least 20"
    );
}

#[test]
fn schemas_reject_bad_documents() {
    let bad = serde_json::json!({"contract_version": "0.1", "module": "x"});
    for schema in [Schema::Status, Schema::BatchStatus, Schema::Manifest] {
        assert!(schema::check(schema, &bad).is_some(), "{schema:?}");
    }
    assert_eq!(
        schema::check(Schema::Error, &serde_json::json!({"message": "x"})).as_deref(),
        Some("/: \"error\" is a required property"),
    );
    assert_eq!(
        schema::check(Schema::Healthz, &read_fixture("healthz-ok.json")),
        None
    );
}

#[test]
fn commands_attention_and_runs_reject_bad_shapes() {
    let manifest = |command: Value| {
        serde_json::json!({
            "contract_version": "0.1", "name": "x", "code": "XX", "version": "1",
            "kind": "batch", "language": "go", "status_command": ["x"],
            "commands": {"c": command},
        })
    };
    let reads = |read: Value| {
        serde_json::json!({
            "contract_version": "0.1", "name": "x", "code": "XX", "version": "1",
            "kind": "batch", "language": "go", "status_command": ["x"],
            "read_commands": {"findings": read},
        })
    };
    let daemon = |ops: Value| {
        serde_json::json!({
            "contract_version": "0.1", "name": "x", "code": "XX", "version": "1",
            "kind": "daemon", "language": "rust", "service_unit": "x.service",
            "base_url": "http://127.0.0.1:1", "openapi_url": "http://127.0.0.1:1/openapi.json",
            "mcp_operations": ops,
        })
    };
    let attention = |entity: Value| {
        serde_json::json!({
            "items": [{"uid": "a", "title": "t", "module": "x", "entities": [entity]}],
            "next_cursor": null,
        })
    };
    let bad = [
        (
            Schema::Manifest,
            manifest(serde_json::json!({"tier": "confirm"})),
        ),
        (
            Schema::Manifest,
            reads(serde_json::json!({"argv": ["x", "list"]})),
        ),
        (
            Schema::Manifest,
            reads(serde_json::json!({"description": "Every finding"})),
        ),
        (
            Schema::Manifest,
            reads(serde_json::json!({"argv": ["x", "list"], "description": ""})),
        ),
        (
            Schema::Manifest,
            reads(serde_json::json!({
                "argv": ["x", "list"], "description": "Every finding", "params": {},
            })),
        ),
        (
            Schema::Attention,
            attention(serde_json::json!({"kind": "finding", "id": "a"})),
        ),
        (Schema::Manifest, daemon(serde_json::json!([]))),
        (Schema::Manifest, daemon(serde_json::json!(["Alerts"]))),
        (
            Schema::Manifest,
            daemon(serde_json::json!(["alerts", "alerts"])),
        ),
        (Schema::Manifest, {
            let mut batch = reads(serde_json::json!(["x", "list"]));
            batch["mcp_operations"] = serde_json::json!(["alerts"]);
            batch
        }),
        (
            Schema::Manifest,
            manifest(serde_json::json!({
                "tier": "confirm", "argv": ["x"], "route": {"method": "POST", "path": "/x"},
            })),
        ),
        (
            Schema::Manifest,
            manifest(serde_json::json!({"tier": "maybe", "argv": ["x"]})),
        ),
        (
            Schema::Manifest,
            manifest(serde_json::json!({
                "tier": "typed", "argv": ["x", "{name}"], "params": {"name": {"pattern": "^a$"}},
            })),
        ),
        (
            Schema::Manifest,
            manifest(
                serde_json::json!({"tier": "safe", "argv": ["x", "{id}"], "params": {"id": {}}}),
            ),
        ),
        (
            Schema::Manifest,
            manifest(serde_json::json!({"tier": "safe", "route": {"method": "GET", "path": "/x"}})),
        ),
        (
            Schema::Manifest,
            manifest(serde_json::json!({"tier": "safe", "argv": ["x"], "body": "json"})),
        ),
        (
            Schema::Manifest,
            manifest(serde_json::json!({
                "tier": "safe", "route": {"method": "POST", "path": "/x"}, "body": "text",
            })),
        ),
        (
            Schema::Manifest,
            manifest(serde_json::json!({"tier": "safe", "argv": ["x"], "title": ""})),
        ),
        (
            Schema::Manifest,
            manifest(serde_json::json!({"tier": "safe", "argv": ["x"], "title": "Add\nnote"})),
        ),
        (
            Schema::Manifest,
            manifest(serde_json::json!({
                "tier": "safe", "route": {"method": "DELETE", "path": "/x"}, "body": "json",
            })),
        ),
        (
            Schema::Manifest,
            manifest(serde_json::json!({
                "tier": "safe", "route": {"method": "POST", "path": "/x"}, "body": "json",
                "inverse": "y",
            })),
        ),
        (
            Schema::Attention,
            serde_json::json!({"items": [{"uid": "a", "module": "x"}], "next_cursor": null}),
        ),
        (
            Schema::Attention,
            serde_json::json!({
                "items": [{"uid": "a", "title": "t", "module": "x", "severity_id": 7}],
                "next_cursor": null,
            }),
        ),
        (
            Schema::Runs,
            serde_json::json!({"module": "x", "runs": [{"id": "1", "started": null, "finished": null}]}),
        ),
        (
            Schema::Runs,
            serde_json::json!({"module": "x", "runs": [
                {"id": "1", "started": null, "finished": null, "outcome": "blocked"},
            ]}),
        ),
    ];
    for (schema, doc) in bad {
        assert!(
            schema::check(schema, &doc).is_some(),
            "{schema:?} accepted {doc}"
        );
    }
    let ok = manifest(serde_json::json!({
        "tier": "safe", "argv": ["x", "{id}"], "params": {"id": {"pattern": "^[0-9]+$"}},
    }));
    assert_eq!(schema::check(Schema::Manifest, &ok), None);
    let ok = manifest(serde_json::json!({
        "tier": "safe", "title": "Add note", "route": {"method": "POST", "path": "/x"},
        "body": "json",
    }));
    assert_eq!(schema::check(Schema::Manifest, &ok), None);
    let ok = reads(serde_json::json!({"argv": ["x", "list"], "description": "Every finding"}));
    assert_eq!(schema::check(Schema::Manifest, &ok), None);
    let ok = daemon(serde_json::json!(["alerts", "alert"]));
    assert_eq!(schema::check(Schema::Manifest, &ok), None);
    let ok = attention(serde_json::json!({"kind": "finding", "id": "x/a"}));
    assert_eq!(schema::check(Schema::Attention, &ok), None);
}

#[test]
fn status_types_round_trip_the_fixtures() {
    for name in ["status-sniffer.json", "status-degraded.json"] {
        let doc = read_fixture(name);
        let typed: DaemonStatus = serde_json::from_value(doc.clone()).unwrap();
        assert!(same(&serde_json::to_value(typed).unwrap(), &doc), "{name}");
    }
    let doc = read_fixture("batch-status-librarian.json");
    let typed: BatchStatus = serde_json::from_value(doc.clone()).unwrap();
    assert!(same(&serde_json::to_value(typed).unwrap(), &doc));
}

#[test]
fn metadata_names_the_writer() {
    let product = Product {
        name: "persist-watch".into(),
        vendor_name: "persist-watch".into(),
        version: "0.1.0".into(),
    };
    let uid = safehouse_core::id::new_event_uid();
    let metadata = Metadata::new(uid.clone(), product.clone(), &["datetime", "host"]);
    assert_eq!(metadata.version, OCSF_VERSION);
    assert_eq!(metadata.product, product);
    assert_eq!(metadata.profiles, ["datetime", "host"]);
    assert_eq!(uuid::Uuid::parse_str(&uid).unwrap().get_version_num(), 7);
}

/// Equal JSON, with numbers compared by value: budgets are `f64`, so `200` comes back
/// as `200.0`.
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| same(x, y))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w)))
        }
        _ => a == b,
    }
}
