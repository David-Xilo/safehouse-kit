//! JSON Lines: one compact JSON object per line (contract "Events").
//!
//! The reader frames lines and parses JSON; the caller turns each value into its own
//! event type and keeps the line number for its errors.

use std::io::{self, BufRead, Read, Write};

use serde::Serialize;
use serde_json::Value;

/// Longest accepted line, excluding the newline. Longer lines are rejected without
/// reading them into memory.
pub const MAX_LINE_BYTES: usize = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum JsonlError {
    #[error("line {line}: {source}")]
    Io { line: u64, source: io::Error },
    #[error("line {line}: longer than {MAX_LINE_BYTES} bytes")]
    LineTooLong { line: u64 },
    #[error("line {line}: {source}")]
    Json {
        line: u64,
        source: serde_json::Error,
    },
}

pub struct JsonlWriter<W: Write> {
    inner: W,
}

impl<W: Write> JsonlWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    pub fn write<T: Serialize + ?Sized>(&mut self, value: &T) -> io::Result<()> {
        serde_json::to_writer(&mut self.inner, value)?;
        self.inner.write_all(b"\n")
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

/// Yields one JSON value per line. A line that is not JSON yields an error and reading
/// continues; an I/O error or an overlong line ends the stream.
pub struct JsonlReader<R: BufRead> {
    inner: R,
    line: u64,
    buf: Vec<u8>,
    done: bool,
}

impl<R: BufRead> JsonlReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            line: 0,
            buf: Vec::new(),
            done: false,
        }
    }

    /// The number of the line read last, from 1.
    pub fn line(&self) -> u64 {
        self.line
    }
}

impl<R: BufRead> Iterator for JsonlReader<R> {
    type Item = Result<Value, JsonlError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        self.buf.clear();
        self.line += 1;
        let line = self.line;
        let limit = MAX_LINE_BYTES as u64 + 1;
        match (&mut self.inner)
            .take(limit)
            .read_until(b'\n', &mut self.buf)
        {
            Ok(0) => {
                self.done = true;
                return None;
            }
            Ok(_) => {}
            Err(source) => {
                self.done = true;
                return Some(Err(JsonlError::Io { line, source }));
            }
        }
        if self.buf.last() == Some(&b'\n') {
            self.buf.pop();
        } else if self.buf.len() > MAX_LINE_BYTES {
            self.done = true;
            return Some(Err(JsonlError::LineTooLong { line }));
        }
        Some(serde_json::from_slice(&self.buf).map_err(|source| JsonlError::Json { line, source }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_lines_and_stops_at_an_overlong_one() {
        let long = "x".repeat(MAX_LINE_BYTES + 1);
        let input = format!("{{\"a\":1}}\nnot json\n{{\"b\":2}}\n{long}\n{{\"c\":3}}\n");
        let got: Vec<_> = JsonlReader::new(input.as_bytes()).collect();
        assert_eq!(got.len(), 4);
        assert_eq!(got[0].as_ref().unwrap()["a"], 1);
        assert!(matches!(got[1], Err(JsonlError::Json { line: 2, .. })));
        assert_eq!(got[2].as_ref().unwrap()["b"], 2);
        assert!(matches!(got[3], Err(JsonlError::LineTooLong { line: 4 })));

        let mut writer = JsonlWriter::new(Vec::new());
        writer.write(&serde_json::json!({"a": 1})).unwrap();
        assert_eq!(writer.into_inner(), b"{\"a\":1}\n");
    }
}
