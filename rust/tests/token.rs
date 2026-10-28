//! The write token on temporary files: what the loader refuses, the Bearer check and the
//! session cookie. Every token here is made up for the test.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use safehouse_core::token::{
    LoadError, MAX_TOKEN_LEN, MIN_TOKEN_LEN, Refused, SESSION_COOKIE, Session, SessionRefused,
    WriteToken,
};

/// 43 base64url characters, the shape `token init` writes.
const TOKEN: &str = "q7Zk2v9XbN4cW1eR8tYuI0oPaSdFgHjKlZxCvBnM-_3";
/// 64 hex digits, the shape `openssl rand -hex 32` writes.
const HEX_TOKEN: &str = "6f1c0b9e2d7a4c3b8e5f0a1d2c3b4a5968778695a4b3c2d1e0f9e8d7c6b5a493"; // gitleaks:allow trufflehog:ignore
const OTHER: &str = "Q7Zk2v9XbN4cW1eR8tYuI0oPaSdFgHjKlZxCvBnM-_3";

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "shc-token-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        Self(dir)
    }

    fn file(&self, text: &[u8], mode: u32) -> PathBuf {
        let path = self.0.join("write.token");
        // An earlier file may be read-only (0400): remove it, do not overwrite it.
        let _ = fs::remove_file(&path);
        fs::write(&path, text).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn load(path: &Path) -> Result<WriteToken, LoadError> {
    WriteToken::load(path)
}

fn token() -> WriteToken {
    WriteToken::parse(TOKEN).unwrap()
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

#[test]
fn loads_a_file_only_its_owner_can_read() {
    let dir = TempDir::new();
    for (text, mode) in [
        (format!("{TOKEN}\n"), 0o600),
        (TOKEN.to_owned(), 0o400),
        (format!("{HEX_TOKEN}\n"), 0o600),
    ] {
        let t = load(&dir.file(text.as_bytes(), mode)).unwrap();
        assert_eq!(t.bearer(), format!("Bearer {}", text.trim_end()));
    }
}

#[test]
fn refuses_group_or_other_access() {
    let dir = TempDir::new();
    for mode in [0o640, 0o604, 0o620, 0o602, 0o660, 0o644, 0o666, 0o610] {
        let err = load(&dir.file(TOKEN.as_bytes(), mode)).unwrap_err();
        assert!(
            matches!(err, LoadError::Mode(m) if m == mode),
            "{mode:o}: {err}"
        );
    }
}

#[test]
fn refuses_a_file_another_user_owns() {
    let caller = rustix::process::geteuid();
    let dir = TempDir::new();
    let path = if caller.is_root() {
        let path = dir.file(TOKEN.as_bytes(), 0o600);
        std::os::unix::fs::chown(&path, Some(65534), Some(65534)).unwrap();
        path
    } else {
        // A file root owns that anyone may open.
        PathBuf::from("/etc/passwd")
    };
    let err = load(&path).unwrap_err();
    assert!(
        matches!(err, LoadError::NotOwned { caller: c, .. } if c == caller.as_raw()),
        "{err}"
    );
}

#[test]
fn refuses_a_symlink_a_directory_and_a_fifo() {
    let dir = TempDir::new();
    let target = dir.file(TOKEN.as_bytes(), 0o600);
    let link = dir.0.join("link.token");
    symlink(&target, &link).unwrap();
    assert!(matches!(load(&link), Err(LoadError::Open(_))));

    let sub = dir.0.join("sub");
    fs::create_dir(&sub).unwrap();
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(load(&sub), Err(LoadError::NotRegular)));

    let fifo = dir.0.join("fifo.token");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    // Opening it would block without a writer, were it not opened non-blocking.
    assert!(matches!(load(&fifo), Err(LoadError::NotRegular)));

    assert!(matches!(
        load(&dir.0.join("missing.token")),
        Err(LoadError::Open(_))
    ));
}

#[test]
fn refuses_a_file_that_holds_no_token() {
    let dir = TempDir::new();
    let short = &TOKEN[..MIN_TOKEN_LEN - 1];
    let long = "a".repeat(MAX_TOKEN_LEN + 1);
    for text in [
        b"".as_slice(),
        b"\n",
        short.as_bytes(),
        long.as_bytes(),
        format!("{TOKEN}\n\n").as_bytes(),
        format!("{TOKEN} ").as_bytes(),
        format!(" {TOKEN}").as_bytes(),
        format!("{TOKEN}\r\n").as_bytes(),
        format!("{TOKEN}=").as_bytes(),
        format!("{TOKEN}+/").as_bytes(),
        b"\xff\xfe not utf-8 at all, but long enough to be a token by length",
    ] {
        let err = load(&dir.file(text, 0o600)).unwrap_err();
        assert!(matches!(err, LoadError::Format), "{err}");
    }
    let big = vec![b'a'; 2048];
    assert!(matches!(
        load(&dir.file(&big, 0o600)),
        Err(LoadError::TooLarge)
    ));
}

#[test]
fn never_prints_the_token() {
    let t = token();
    assert!(!format!("{t:?}").contains(TOKEN));
    let near = format!("{TOKEN}!");
    let err = WriteToken::parse(&near).unwrap_err();
    assert!(!err.to_string().contains(&TOKEN[..10]));
    let refused = t.check_bearer(Some(format!("Bearer {OTHER}").as_bytes()));
    assert!(!format!("{refused:?}").contains(&OTHER[..10]));
}

#[test]
fn bearer_accepts_the_token_only() {
    let t = token();
    let ok = |v: &str| t.check_bearer(Some(v.as_bytes()));
    assert_eq!(ok(&format!("Bearer {TOKEN}")), Ok(()));
    assert_eq!(ok(&format!("bearer {TOKEN}")), Ok(()));
    assert_eq!(ok(&format!("BEARER  {TOKEN} ")), Ok(()));
    assert_eq!(ok(&t.bearer()), Ok(()));

    assert_eq!(t.check_bearer(None), Err(Refused::Missing));
    assert_eq!(ok(&format!("Bearer {OTHER}")), Err(Refused::Wrong));
    assert_eq!(ok(&format!("Bearer {}", &TOKEN[1..])), Err(Refused::Wrong));
    assert_eq!(ok(&format!("Bearer {TOKEN}x")), Err(Refused::Wrong));
    assert_eq!(ok(&format!("Bearer {TOKEN} {TOKEN}")), Err(Refused::Wrong));
    assert_eq!(
        ok(&format!("Bearer {}", "a".repeat(10_000))),
        Err(Refused::Wrong)
    );
    assert_eq!(ok(&format!("Basic {TOKEN}")), Err(Refused::Malformed));
    assert_eq!(ok(&format!("Bearer{TOKEN}")), Err(Refused::Malformed));
    assert_eq!(ok("Bearer "), Err(Refused::Malformed));
    assert_eq!(ok(""), Err(Refused::Malformed));
    assert_eq!(ok(TOKEN), Err(Refused::Malformed));
    assert_eq!(
        t.check_bearer(Some(b"Bearer \xff\xfe")),
        Err(Refused::Wrong)
    );
}

#[test]
fn session_cookie_round_trips() {
    let t = token();
    let now = at(1_800_000_000);
    let (session, value) = t.new_session(now, Duration::from_secs(3600));
    assert_eq!(session.id.len(), 32);
    assert_eq!(session.expires_at, 1_800_003_600);
    assert!(!value.contains(TOKEN));
    assert_eq!(t.check_session(value.as_bytes(), now), Ok(session.clone()));
    assert_eq!(
        t.check_session(value.as_bytes(), at(1_800_003_599)),
        Ok(session.clone())
    );

    let header = format!("theme=dark; {SESSION_COOKIE}={value}; other=1");
    assert_eq!(t.check_cookie(Some(header.as_bytes()), now), Ok(session));

    let (other, _) = t.new_session(now, Duration::from_secs(3600));
    let (third, _) = t.new_session(now, Duration::from_secs(3600));
    assert_ne!(other.id, third.id);
}

#[test]
fn set_cookie_keeps_the_session_from_scripts_and_other_sites() {
    let t = token();
    let now = at(1_800_000_000);
    let (session, value) = t.new_session(now, Duration::from_secs(600));
    assert_eq!(
        t.set_cookie(&session, now),
        format!("{SESSION_COOKIE}={value}; Max-Age=600; Path=/; HttpOnly; SameSite=Strict")
    );
    let late = t.set_cookie(&session, at(1_800_000_700));
    assert!(late.contains("; Max-Age=0;"), "{late}");
}

#[test]
fn session_cookie_refuses_expired_forged_and_malformed() {
    let t = token();
    let now = at(1_800_000_000);
    let (session, value) = t.new_session(now, Duration::from_secs(60));
    let check = |v: &str| t.check_session(v.as_bytes(), now);

    assert_eq!(
        t.check_session(value.as_bytes(), at(1_800_000_060)),
        Err(SessionRefused::Expired)
    );

    // A new token ends every session.
    let rotated = WriteToken::parse(OTHER).unwrap();
    assert_eq!(
        rotated.check_session(value.as_bytes(), now),
        Err(SessionRefused::Forged)
    );

    let mac = value.rsplit_once('.').unwrap().1;
    // A later expiry or another id under the old MAC.
    assert_eq!(
        check(&format!(
            "v1.{}.{}.{mac}",
            session.id,
            session.expires_at + 3600
        )),
        Err(SessionRefused::Forged)
    );
    assert_eq!(
        check(&format!(
            "v1.{}.{}.{mac}",
            "a".repeat(32),
            session.expires_at
        )),
        Err(SessionRefused::Forged)
    );
    // One flipped MAC digit.
    let mut flipped = value.clone().into_bytes();
    let last = flipped.len() - 1;
    flipped[last] = if flipped[last] == b'0' { b'1' } else { b'0' };
    assert_eq!(t.check_session(&flipped, now), Err(SessionRefused::Forged));
    // A cookie this token signed for another session id is not this session.
    let forged = Session {
        id: "attacker".into(),
        expires_at: u64::MAX,
    };
    let foreign = rotated.set_cookie(&forged, now);
    let foreign_value = foreign
        .split_once('=')
        .unwrap()
        .1
        .split_once(';')
        .unwrap()
        .0;
    assert_eq!(check(foreign_value), Err(SessionRefused::Forged));

    for bad in [
        String::new(),
        "v1".into(),
        format!("v2.{}.{}.{mac}", session.id, session.expires_at),
        format!("v1.{}.{}", session.id, session.expires_at),
        format!("v1..{}.{mac}", session.expires_at),
        format!("v1.{}..{mac}", session.id),
        format!("v1.{}.+{}.{mac}", session.id, session.expires_at),
        format!("v1.{}.99999999999999999999999.{mac}", session.id),
        format!("v1.a.b.{}.{}.{mac}", session.id, session.expires_at),
        format!(
            "v1.{}.{}.{}",
            session.id,
            session.expires_at,
            mac.to_uppercase()
        ),
        format!("v1.{}.{}.{}", session.id, session.expires_at, &mac[1..]),
        format!("v1.{} x.{}.{mac}", session.id, session.expires_at),
        format!("v1.{}.{}.{mac}", "a".repeat(65), session.expires_at),
    ] {
        assert_eq!(check(&bad), Err(SessionRefused::Malformed), "{bad}");
    }
    assert_eq!(
        t.check_session(b"\xff.\xfe", now),
        Err(SessionRefused::Malformed)
    );
}

#[test]
fn cookie_header_needs_exactly_one_session_cookie() {
    let t = token();
    let now = at(1_800_000_000);
    let (_, value) = t.new_session(now, Duration::from_secs(60));
    assert_eq!(t.check_cookie(None, now), Err(SessionRefused::Missing));
    assert_eq!(
        t.check_cookie(Some(b"theme=dark; x=1"), now),
        Err(SessionRefused::Missing)
    );
    assert_eq!(
        t.check_cookie(Some(format!("x{SESSION_COOKIE}={value}").as_bytes()), now),
        Err(SessionRefused::Missing)
    );
    let twice = format!("{SESSION_COOKIE}={value}; {SESSION_COOKIE}={value}");
    assert_eq!(
        t.check_cookie(Some(twice.as_bytes()), now),
        Err(SessionRefused::Malformed)
    );
}
