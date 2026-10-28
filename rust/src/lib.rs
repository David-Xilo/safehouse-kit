//! safehouse shared core for Rust modules.
//!
//! The module contract lives in `contract/` beside this crate; this crate types the parts
//! that two Rust modules would otherwise copy. Using it is optional: a module meets the
//! contract through files, HTTP and schemas.
//!
//! Features: `openapi` (utoipa schemas), `redact` (the rule loader over
//! `contract/rules/`), `schema` (validation against `contract/schemas/`), `local-model`
//! (the Ollama client, [`local`]), `write-token` (the local write token and the console's
//! session cookie, [`token`]).

pub mod id;
pub mod jsonl;
#[cfg(feature = "local-model")]
pub mod local;
pub mod ocsf;
#[cfg(feature = "redact")]
pub mod redact;
#[cfg(feature = "schema")]
pub mod schema;
pub mod status;
#[cfg(feature = "write-token")]
pub mod token;
