//! Append-only audit log. Each JSON line carries the SHA-256 of its own content and the hash
//! of the previous line, so editing, dropping or reordering lines breaks the chain.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// Forwarded unchanged.
    Message { dir: Direction, msg: Value },
    /// Not forwarded.
    Rejected { dir: Direction, reason: String },
    /// Sent to the client by the gateway in place of the server.
    Reply { msg: Value },
    /// A gateway decision about the preceding message.
    Finding { finding: custody_core::Finding },
    /// The downstream server exited; `code` is `None` when it was killed by a signal.
    Exit { code: Option<i32> },
}

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    seq: u64,
    ts_ms: u64,
    #[serde(flatten)]
    event: Event,
    prev: String,
    hash: String,
}

// What the hash covers: every field of `Entry` except `hash` itself.
#[derive(Serialize)]
struct Unsigned<'a> {
    seq: u64,
    ts_ms: u64,
    #[serde(flatten)]
    event: &'a Event,
    prev: &'a str,
}

impl Unsigned<'_> {
    fn hash(&self) -> Result<String, serde_json::Error> {
        // serde_json sorts object keys (no `preserve_order`), so re-serializing a parsed line
        // reproduces these exact bytes.
        let bytes = serde_json::to_vec(self)?;
        Ok(hex::encode(Sha256::digest(&bytes)))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit log io")]
    Io(#[from] io::Error),
    #[error("audit log encoding")]
    Json(#[from] serde_json::Error),
    #[error("audit log lock poisoned")]
    Poisoned,
}

#[derive(Debug)]
struct State {
    out: BufWriter<File>,
    seq: u64,
    prev: String,
}

#[derive(Debug)]
pub struct Audit {
    state: Mutex<State>,
}

impl Audit {
    /// Refuses to open an existing file: appending to an old log would start a second chain.
    pub fn create(path: &Path) -> Result<Self, AuditError> {
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        Ok(Self {
            state: Mutex::new(State {
                out: BufWriter::new(file),
                seq: 0,
                prev: GENESIS.to_owned(),
            }),
        })
    }

    /// Writes and flushes the record before returning, so callers can log before acting.
    pub fn record(&self, event: Event) -> Result<(), AuditError> {
        let mut state = self.state.lock().map_err(|_| AuditError::Poisoned)?;
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let unsigned = Unsigned {
            seq: state.seq,
            ts_ms,
            event: &event,
            prev: &state.prev,
        };
        let hash = unsigned.hash()?;
        let entry = Entry {
            seq: state.seq,
            ts_ms,
            event,
            prev: state.prev.clone(),
            hash: hash.clone(),
        };
        serde_json::to_writer(&mut state.out, &entry)?;
        state.out.write_all(b"\n")?;
        state.out.flush()?;
        state.seq += 1;
        state.prev = hash;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("line {line}: {reason}")]
pub struct VerifyError {
    pub line: u64,
    pub reason: String,
}

/// Returns the number of records if the chain is intact.
pub fn verify(path: &Path) -> Result<u64, VerifyError> {
    let fail = |line: u64, reason: String| VerifyError { line, reason };
    let file = File::open(path).map_err(|e| fail(0, e.to_string()))?;
    let mut prev = GENESIS.to_owned();
    let mut count = 0;
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let n = i as u64 + 1;
        let line = line.map_err(|e| fail(n, e.to_string()))?;
        let entry: Entry = serde_json::from_str(&line).map_err(|e| fail(n, e.to_string()))?;
        if entry.seq != count {
            return Err(fail(
                n,
                format!("expected seq {count}, found {}", entry.seq),
            ));
        }
        if entry.prev != prev {
            return Err(fail(n, "previous hash does not match".into()));
        }
        let unsigned = Unsigned {
            seq: entry.seq,
            ts_ms: entry.ts_ms,
            event: &entry.event,
            prev: &entry.prev,
        };
        let expected = unsigned.hash().map_err(|e| fail(n, e.to_string()))?;
        if entry.hash != expected {
            return Err(fail(n, "record hash does not match its content".into()));
        }
        prev = entry.hash;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;

    fn temp_path(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("custody-audit-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn write_sample(path: &Path) {
        let audit = Audit::create(path).unwrap();
        let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"x": 1.5}});
        audit
            .record(Event::Message {
                dir: Direction::ClientToServer,
                msg,
            })
            .unwrap();
        audit
            .record(Event::Rejected {
                dir: Direction::ServerToClient,
                reason: "bad".into(),
            })
            .unwrap();
        audit.record(Event::Exit { code: Some(0) }).unwrap();
    }

    fn rewrite(path: &Path, f: impl FnOnce(&mut Vec<String>)) {
        let mut lines: Vec<String> = std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        f(&mut lines);
        std::fs::write(path, lines.join("\n") + "\n").unwrap();
    }

    #[test]
    fn intact_log_verifies() {
        let p = temp_path("intact");
        write_sample(&p);
        assert_eq!(verify(&p).unwrap(), 3);
    }

    #[test]
    fn refuses_existing_file() {
        let p = temp_path("existing");
        write_sample(&p);
        assert!(Audit::create(&p).is_err());
    }

    #[test]
    fn edited_record_is_detected() {
        let p = temp_path("edited");
        write_sample(&p);
        rewrite(&p, |l| l[0] = l[0].replace("tools/call", "tools/list"));
        assert_eq!(verify(&p).unwrap_err().line, 1);
    }

    #[test]
    fn dropped_record_is_detected() {
        let p = temp_path("dropped");
        write_sample(&p);
        rewrite(&p, |l| {
            l.remove(1);
        });
        assert_eq!(verify(&p).unwrap_err().line, 2);
    }
}
