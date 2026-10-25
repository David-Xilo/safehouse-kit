//! A client for a local model on Ollama: one
//! `POST {base}/api/chat` whose reply must match a JSON schema, on a model pinned by
//! digest. The sniffer and the hub share this copy.
//!
//! Strict-local: the base URL must be a loopback address, so a prompt never leaves the
//! host and needs no redaction here. Errors carry statuses, names and counts, never the
//! prompt, the reply or a response body (it may echo the prompt).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ureq::http::Uri;

/// Ollama's default address.
pub const DEFAULT_BASE_URL: &str = "http://127.0.0.1:11434";

/// A cold start loads the model before it answers.
const TIMEOUT: Duration = Duration::from_secs(120);
const MAX_RESPONSE_BYTES: u64 = 1 << 20;
const BUILTIN_TIERS: &str = include_str!("../local-tiers.toml");

/// The local tier aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    /// 7–8B.
    LocalSmall,
    /// 14B.
    LocalMid,
    /// 24–32B, quantized to fit 16 GiB.
    LocalStrong,
}

impl Tier {
    pub fn name(self) -> &'static str {
        match self {
            Self::LocalSmall => "local-small",
            Self::LocalMid => "local-mid",
            Self::LocalStrong => "local-strong",
        }
    }
}

/// One installed model, as Ollama names and hashes it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    /// The name with its tag, as `ollama list` shows it (`qwen2.5:7b`).
    pub model: String,
    /// The manifest's sha256, 64 lowercase hex digits.
    pub digest: String,
    /// Ollama's `quantization_level` (`Q4_K_M`).
    pub quantization: String,
    /// The context window each call asks for, in tokens.
    pub num_ctx: u32,
}

/// The model behind each tier; a tier without a pin cannot be asked.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Tiers {
    pub local_small: Option<Pin>,
    pub local_mid: Option<Pin>,
    pub local_strong: Option<Pin>,
}

impl Tiers {
    /// The built-in pins (`local-tiers.toml`).
    pub fn builtin() -> Self {
        Self::parse(BUILTIN_TIERS).expect("the built-in tiers are valid")
    }

    /// Tiers from TOML: a `[local-small]`, `[local-mid]` or `[local-strong]` table each.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let tiers: Self = toml::from_str(text).map_err(|e| Error::Tiers(e.message().into()))?;
        let pins = [Tier::LocalSmall, Tier::LocalMid, Tier::LocalStrong]
            .into_iter()
            .filter_map(|tier| Some((tier, tiers.get(tier)?)));
        for (tier, pin) in pins {
            let hex = pin.digest.len() == 64
                && pin
                    .digest
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
            let problem = if pin.model.is_empty() || pin.quantization.is_empty() {
                Some("an empty model or quantization")
            } else if !pin.model.contains(':') {
                // Ollama lists every model with its tag (`qwen2.5:latest`).
                Some("a model without its tag")
            } else if !hex {
                Some("a digest other than 64 lowercase hex digits")
            } else if pin.num_ctx == 0 {
                Some("num_ctx 0")
            } else {
                None
            };
            if let Some(problem) = problem {
                return Err(Error::Tiers(format!("{}: {problem}", tier.name())));
            }
        }
        Ok(tiers)
    }

    pub fn get(&self, tier: Tier) -> Option<&Pin> {
        match tier {
            Tier::LocalSmall => self.local_small.as_ref(),
            Tier::LocalMid => self.local_mid.as_ref(),
            Tier::LocalStrong => self.local_strong.as_ref(),
        }
    }
}

/// What one call asks.
#[derive(Debug, Clone, Copy)]
pub struct Prompt<'a> {
    pub system: &'a str,
    pub user: &'a str,
    /// The JSON schema the reply must match: Ollama constrains its output to it, the
    /// client validates the reply against it, then parses it into the caller's type.
    pub schema: &'a Value,
    /// The most tokens the model may write; a reply cut there is refused.
    pub max_tokens: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// One call's typed reply and what it cost.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply<T> {
    pub value: T,
    /// The model that answered, the pin's name (control characters removed). Its digest
    /// matched the pin just before the call.
    pub model: String,
    pub usage: Usage,
    /// The time Ollama spent loading the model; zero when it was loaded already.
    pub load: Duration,
    /// From the start of the call (the schema's compile and the digest check) to the end
    /// of the reply.
    pub latency: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the local model's base URL must be a loopback address (strict-local)")]
    BaseUrl,
    #[error("local tiers: {0}")]
    Tiers(String),
    #[error("no pin for {0}")]
    NoPin(&'static str),
    /// The installed model is missing or is not the pinned one.
    #[error("model {model}: {problem}")]
    Pin {
        model: String,
        problem: &'static str,
    },
    #[error("the prompt's schema is not a valid JSON schema: nothing sent")]
    Schema,
    #[error("Ollama answered HTTP {0}")]
    Status(u16),
    #[error("Ollama request failed: {0}")]
    Transport(&'static str),
    #[error("Ollama response is invalid: {0}")]
    Invalid(&'static str),
}

/// A client for one Ollama daemon on this host.
#[derive(Debug)]
pub struct Client {
    agent: ureq::Agent,
    base: String,
}

impl Client {
    /// A client for `base`: `http` to a loopback IP address, with no query or fragment.
    /// A name, `localhost` too, is refused: the resolver could map it off the host. So is
    /// `https`: Ollama serves plain HTTP, and no public CA signs a loopback address.
    pub fn new(base: &str) -> Result<Self, Error> {
        let uri: Uri = base.parse().map_err(|_| Error::BaseUrl)?;
        let host = uri.host().unwrap_or_default().trim_matches(['[', ']']);
        let loopback = host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
        let plain = uri.query().is_none() && !base.contains('#');
        if !loopback || !plain || uri.scheme_str() != Some("http") {
            return Err(Error::BaseUrl);
        }
        Ok(Self {
            agent: agent(TIMEOUT),
            base: base.trim_end_matches('/').into(),
        })
    }

    /// The limit on each request, from connecting to the end of the response.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.agent = agent(timeout);
        self
    }

    /// Asks the model behind `tier` in `tiers`.
    pub fn ask_tier<T: DeserializeOwned>(
        &self,
        tiers: &Tiers,
        tier: Tier,
        prompt: &Prompt,
    ) -> Result<Reply<T>, Error> {
        let pin = tiers.get(tier).ok_or(Error::NoPin(tier.name()))?;
        self.ask(pin, prompt)
    }

    /// Checks that the installed model matches `pin`, then asks it `prompt` once, at
    /// temperature 0, with the pin's context window. No retry: a failed local call
    /// leaves the caller's rules-only answer in place.
    pub fn ask<T: DeserializeOwned>(&self, pin: &Pin, prompt: &Prompt) -> Result<Reply<T>, Error> {
        let started = Instant::now();
        let validator = jsonschema::validator_for(prompt.schema).map_err(|_| Error::Schema)?;
        self.check(pin)?;
        let body = serde_json::to_string(&ChatRequest {
            model: &pin.model,
            messages: [
                Message {
                    role: "system",
                    content: prompt.system,
                },
                Message {
                    role: "user",
                    content: prompt.user,
                },
            ],
            format: prompt.schema,
            stream: false,
            options: Options {
                num_ctx: pin.num_ctx,
                num_predict: prompt.max_tokens,
                temperature: 0.0,
            },
        })
        .map_err(|_| Error::Invalid("request not serializable"))?;
        let request = self.agent.post(format!("{}/api/chat", self.base));
        let response = request
            .header("Content-Type", "application/json")
            .send(&body);
        let chat: ChatResponse = read(response)?;
        if !chat.done {
            return Err(Error::Invalid("reply not done"));
        }
        if chat.done_reason.as_deref() == Some("length") {
            return Err(Error::Invalid("reply cut at max_tokens"));
        }
        if chat.model != pin.model {
            return Err(Error::Pin {
                model: printable(&pin.model),
                problem: "another model answered",
            });
        }
        let mismatch = || Error::Invalid("reply does not match the schema");
        let reply: Value = serde_json::from_str(&chat.message.content).map_err(|_| mismatch())?;
        if !validator.is_valid(&reply) {
            return Err(mismatch());
        }
        let value = serde_json::from_value(reply).map_err(|_| mismatch())?;
        Ok(Reply {
            value,
            model: printable(&chat.model),
            usage: Usage {
                input_tokens: chat.prompt_eval_count.unwrap_or(0),
                output_tokens: chat.eval_count.unwrap_or(0),
            },
            load: Duration::from_nanos(chat.load_duration.unwrap_or(0)),
            latency: started.elapsed(),
        })
    }

    /// Refuses a model that is missing, or whose digest or quantization is not the pin's.
    fn check(&self, pin: &Pin) -> Result<(), Error> {
        let response = self.agent.get(format!("{}/api/tags", self.base)).call();
        let tags: Tags = read(response)?;
        let refused = |problem| Error::Pin {
            model: printable(&pin.model),
            problem,
        };
        let model = tags
            .models
            .iter()
            .find(|m| m.name == pin.model)
            .ok_or_else(|| refused("not installed"))?;
        if model.digest != pin.digest {
            return Err(refused("digest differs from the pin"));
        }
        let quantization = model
            .details
            .as_ref()
            .map(|d| d.quantization_level.as_str());
        if quantization != Some(pin.quantization.as_str()) {
            return Err(refused("quantization differs from the pin"));
        }
        Ok(())
    }
}

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        // A proxy from the environment or a redirect would carry the prompt off the host.
        .proxy(None)
        .max_redirects(0)
        .build()
        .into()
}

/// A 200 response's JSON body, at most 1 MiB.
fn read<T: DeserializeOwned>(
    response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<T, Error> {
    let mut response = response.map_err(|e| transport(&e))?;
    match response.status().as_u16() {
        200 => {}
        status => return Err(Error::Status(status)),
    }
    let data = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_to_vec()
        .map_err(|e| match e {
            ureq::Error::BodyExceedsLimit(_) => Error::Invalid("response larger than 1 MiB"),
            e => transport(&e),
        })?;
    serde_json::from_slice(&data).map_err(|_| Error::Invalid("not an Ollama response"))
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: [Message<'a>; 2],
    format: &'a Value,
    stream: bool,
    options: Options,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct Options {
    num_ctx: u32,
    num_predict: u32,
    temperature: f64,
}

#[derive(Deserialize)]
struct ChatResponse {
    model: String,
    message: ReplyMessage,
    done: bool,
    done_reason: Option<String>,
    prompt_eval_count: Option<u64>,
    eval_count: Option<u64>,
    /// Nanoseconds.
    load_duration: Option<u64>,
}

#[derive(Deserialize)]
struct ReplyMessage {
    content: String,
}

#[derive(Deserialize)]
struct Tags {
    models: Vec<Tag>,
}

/// An entry of the listing; a model other than the pinned one may lack any field but its
/// name, and must not break the listing.
#[derive(Deserialize)]
struct Tag {
    name: String,
    #[serde(default)]
    digest: String,
    #[serde(default)]
    details: Option<TagDetails>,
}

#[derive(Deserialize)]
struct TagDetails {
    #[serde(default)]
    quantization_level: String,
}

/// A ureq error in a few words, without the URL or any body.
fn transport(error: &ureq::Error) -> Error {
    use std::io::ErrorKind;
    Error::Transport(match error {
        ureq::Error::Timeout(_) => "timeout",
        ureq::Error::Io(e) if e.kind() == ErrorKind::TimedOut => "timeout",
        ureq::Error::HostNotFound => "host not found",
        ureq::Error::ConnectionFailed => "connection failed",
        ureq::Error::Io(e) if e.kind() == ErrorKind::ConnectionRefused => "connection refused",
        _ => "connection failed",
    })
}

/// Drops control characters, so a name from the server cannot rewrite a log line.
fn printable(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}
