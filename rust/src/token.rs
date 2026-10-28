//! The local write token: one random secret in a file that only its owner can read. A
//! daemon refuses a write without `Authorization: Bearer <token>`; the gateway, the only
//! caller that sends the token, also signs its console's session cookie with it, so a
//! new token ends every session.
//!
//! The token never leaves a [`WriteToken`]: no `Display`, no `Serialize`, and `Debug`
//! prints nothing of it. Errors name the reason only, never the file's text or a path.
//! Only [`WriteToken::bearer`] hands it out, for the one caller that sends it.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use rustix::fs::{Mode, OFlags};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// The shortest token: 43 base64url characters hold 32 random bytes.
pub const MIN_TOKEN_LEN: usize = 43;
/// The longest token.
pub const MAX_TOKEN_LEN: usize = 256;
/// The session cookie's name.
pub const SESSION_COOKIE: &str = "safehouse_session";

/// A file larger than this is not a token file.
const MAX_FILE_BYTES: u64 = 1024;
/// Separates the session key from any other use of the token.
const SESSION_KEY_LABEL: &[u8] = b"safehouse-core session cookie v1";
const SESSION_VERSION: &str = "v1";
const MAC_HEX_LEN: usize = 64;
const MAX_SESSION_ID_LEN: usize = 64;

/// Why a token file was refused.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("token file: open: {0}")]
    Open(std::io::Error),
    #[error("token file: read: {0}")]
    Read(std::io::Error),
    #[error("token file: not a regular file")]
    NotRegular,
    #[error("token file: owned by uid {owner}, not by the caller ({caller})")]
    NotOwned { owner: u32, caller: u32 },
    #[error("token file: mode {0:o} gives group or others access; want 600 or 400")]
    Mode(u32),
    #[error("token file: larger than {MAX_FILE_BYTES} bytes")]
    TooLarge,
    #[error(
        "token: want {MIN_TOKEN_LEN} to {MAX_TOKEN_LEN} characters of A-Z, a-z, 0-9, '-' and '_', and at most one final newline"
    )]
    Format,
}

/// Why a write's `Authorization` header was refused. A daemon answers 401 to each and
/// counts them; none says which part of the token was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    #[error("no Authorization header")]
    Missing,
    #[error("Authorization is not a Bearer token")]
    Malformed,
    #[error("wrong token")]
    Wrong,
}

/// Why a session cookie was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionRefused {
    #[error("no session cookie")]
    Missing,
    #[error("session cookie is malformed")]
    Malformed,
    #[error("session cookie is not signed by this token")]
    Forged,
    #[error("session expired")]
    Expired,
}

/// One console session. The id is not secret: it names the session in an audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// A UUIDv7 in simple form (32 lowercase hex digits) for a session made here.
    pub id: String,
    /// Seconds since the Unix epoch; the session ends at this second.
    pub expires_at: u64,
}

/// The write token, loaded once at start.
pub struct WriteToken {
    token: String,
    bearer_digest: [u8; 32],
    session_key: [u8; 32],
}

impl std::fmt::Debug for WriteToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WriteToken(..)")
    }
}

impl WriteToken {
    /// Loads the token file. Refuses a symlink, anything but a regular file, a file not
    /// owned by the effective uid, and one with any group or other permission bit. The
    /// checks run on the opened file, so a swap after them changes nothing.
    pub fn load(path: &Path) -> Result<Self, LoadError> {
        // NONBLOCK: opening a FIFO in place of the file must not hang.
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY;
        let fd = rustix::fs::open(path, flags | OFlags::NONBLOCK, Mode::empty())
            .map_err(|e| LoadError::Open(e.into()))?;
        let file = File::from(fd);
        let meta = file.metadata().map_err(LoadError::Read)?;
        if !meta.file_type().is_file() {
            return Err(LoadError::NotRegular);
        }
        let caller = rustix::process::geteuid().as_raw();
        if meta.uid() != caller {
            return Err(LoadError::NotOwned {
                owner: meta.uid(),
                caller,
            });
        }
        if meta.mode() & 0o077 != 0 {
            return Err(LoadError::Mode(meta.mode() & 0o7777));
        }
        if meta.len() > MAX_FILE_BYTES {
            return Err(LoadError::TooLarge);
        }
        let mut text = String::new();
        file.take(MAX_FILE_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::InvalidData => LoadError::Format,
                _ => LoadError::Read(e),
            })?;
        if text.len() as u64 > MAX_FILE_BYTES {
            return Err(LoadError::TooLarge);
        }
        Self::parse(&text)
    }

    /// A token from its text, as the file holds it: [`MIN_TOKEN_LEN`] to
    /// [`MAX_TOKEN_LEN`] characters of the base64url alphabet (hex is a subset), and at
    /// most one final newline. For tests and for a caller that read the file itself.
    pub fn parse(text: &str) -> Result<Self, LoadError> {
        let token = text.strip_suffix('\n').unwrap_or(text);
        if !is_token(token.as_bytes()) {
            return Err(LoadError::Format);
        }
        let mut mac = new_mac(token.as_bytes());
        mac.update(SESSION_KEY_LABEL);
        Ok(Self {
            token: token.to_owned(),
            bearer_digest: Sha256::digest(token.as_bytes()).into(),
            session_key: mac.finalize().into_bytes().into(),
        })
    }

    /// The `Authorization` header value that carries the token. Only the caller that
    /// sends writes needs it; never log it.
    pub fn bearer(&self) -> String {
        format!("Bearer {}", self.token)
    }

    /// Checks a write's `Authorization` header value. The token comparison takes the
    /// same time whatever the presented value: both sides are hashed first, then
    /// compared in constant time.
    pub fn check_bearer(&self, authorization: Option<&[u8]>) -> Result<(), Refused> {
        let value = authorization.ok_or(Refused::Missing)?;
        let (scheme, rest) = split_once(value, b' ').ok_or(Refused::Malformed)?;
        if !scheme.eq_ignore_ascii_case(b"Bearer") {
            return Err(Refused::Malformed);
        }
        let presented = rest.trim_ascii();
        if presented.is_empty() {
            return Err(Refused::Malformed);
        }
        if presented.len() > MAX_TOKEN_LEN {
            return Err(Refused::Wrong);
        }
        let digest: [u8; 32] = Sha256::digest(presented).into();
        if bool::from(digest.ct_eq(&self.bearer_digest)) {
            Ok(())
        } else {
            Err(Refused::Wrong)
        }
    }

    /// A new session that ends `ttl` after `now`, and its signed cookie value.
    pub fn new_session(&self, now: SystemTime, ttl: Duration) -> (Session, String) {
        let session = Session {
            id: Uuid::now_v7().simple().to_string(),
            expires_at: unix_seconds(now).saturating_add(ttl.as_secs()),
        };
        let value = self.sign_session(&session);
        (session, value)
    }

    /// The `Set-Cookie` header value for a session: HttpOnly so no script reads it,
    /// SameSite=Strict so no other site's page sends it, and Max-Age to its end. No
    /// `Secure`: the console is served over plain HTTP on a loopback address.
    pub fn set_cookie(&self, session: &Session, now: SystemTime) -> String {
        let max_age = session.expires_at.saturating_sub(unix_seconds(now));
        format!(
            "{SESSION_COOKIE}={}; Max-Age={max_age}; Path=/; HttpOnly; SameSite=Strict",
            self.sign_session(session)
        )
    }

    /// The session in a request's `Cookie` header value, if its cookie is signed by this
    /// token and has not ended at `now`. The MAC is checked in constant time before the
    /// expiry is read.
    pub fn check_cookie(
        &self,
        cookie_header: Option<&[u8]>,
        now: SystemTime,
    ) -> Result<Session, SessionRefused> {
        let header = cookie_header.ok_or(SessionRefused::Missing)?;
        let mut found = None;
        for pair in header.split(|&b| b == b';') {
            let Some((name, value)) = split_once(pair.trim_ascii(), b'=') else {
                continue;
            };
            if name == SESSION_COOKIE.as_bytes() {
                // Two cookies of one name: a page on the same site may have set one.
                if found.is_some() {
                    return Err(SessionRefused::Malformed);
                }
                found = Some(value);
            }
        }
        self.check_session(found.ok_or(SessionRefused::Missing)?, now)
    }

    /// Checks one session cookie value (`v1.<id>.<expires_at>.<mac>`).
    pub fn check_session(&self, value: &[u8], now: SystemTime) -> Result<Session, SessionRefused> {
        let value = std::str::from_utf8(value).map_err(|_| SessionRefused::Malformed)?;
        let (signed, mac_hex) = value.rsplit_once('.').ok_or(SessionRefused::Malformed)?;
        let mut parts = signed.split('.');
        let (Some(version), Some(id), Some(expires), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(SessionRefused::Malformed);
        };
        if version != SESSION_VERSION
            || !is_session_id(id)
            || expires.is_empty()
            || !expires.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(SessionRefused::Malformed);
        }
        let expires_at: u64 = expires.parse().map_err(|_| SessionRefused::Malformed)?;
        let mac = decode_hex(mac_hex).ok_or(SessionRefused::Malformed)?;
        let mut check = new_mac(&self.session_key);
        check.update(signed.as_bytes());
        check
            .verify_slice(&mac)
            .map_err(|_| SessionRefused::Forged)?;
        if unix_seconds(now) >= expires_at {
            return Err(SessionRefused::Expired);
        }
        Ok(Session {
            id: id.to_owned(),
            expires_at,
        })
    }

    fn sign_session(&self, session: &Session) -> String {
        let signed = format!("{SESSION_VERSION}.{}.{}", session.id, session.expires_at);
        let mut mac = new_mac(&self.session_key);
        mac.update(signed.as_bytes());
        let tag = mac.finalize().into_bytes();
        let mut value = signed;
        value.push('.');
        for b in tag {
            value.push_str(&format!("{b:02x}"));
        }
        value
    }
}

fn new_mac(key: &[u8]) -> HmacSha256 {
    <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC takes a key of any length")
}

fn is_token(token: &[u8]) -> bool {
    (MIN_TOKEN_LEN..=MAX_TOKEN_LEN).contains(&token.len())
        && token
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_session_id(id: &str) -> bool {
    (1..=MAX_SESSION_ID_LEN).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn split_once(bytes: &[u8], sep: u8) -> Option<(&[u8], &[u8])> {
    let at = bytes.iter().position(|&b| b == sep)?;
    Some((&bytes[..at], &bytes[at + 1..]))
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() != MAC_HEX_LEN {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digit = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                _ => None,
            };
            Some(digit(pair[0])? << 4 | digit(pair[1])?)
        })
        .collect()
}

fn unix_seconds(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}
