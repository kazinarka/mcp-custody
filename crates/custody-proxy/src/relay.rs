//! Transparent stdio relay between an MCP client (our stdin/stdout) and a server subprocess.
//!
//! MCP stdio frames are newline-delimited JSON. Every frame that parses as JSON is logged and
//! forwarded byte for byte. A frame that does not parse is logged and dropped: anything the
//! gateway cannot inspect must not pass.

use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, bail};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Command;

use crate::audit::{Audit, Direction, Event};

#[derive(Debug)]
pub struct Config {
    pub command: Vec<String>,
    pub max_message_bytes: usize,
}

/// Runs until the server exits and returns its exit code.
pub async fn run(config: Config, audit: Option<Audit>) -> anyhow::Result<i32> {
    let audit = Arc::new(audit);
    let (program, args) = config
        .command
        .split_first()
        .context("empty server command")?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to start {program}"))?;
    let child_in = child.stdin.take().context("server stdin")?;
    let child_out = child.stdout.take().context("server stdout")?;
    let max = config.max_message_bytes;

    let mut upstream = tokio::spawn(pump(
        tokio::io::stdin(),
        child_in,
        Direction::ClientToServer,
        Arc::clone(&audit),
        max,
    ));
    let downstream = pump(
        child_out,
        tokio::io::stdout(),
        Direction::ServerToClient,
        Arc::clone(&audit),
        max,
    );
    tokio::pin!(downstream);

    tokio::select! {
        // Client finished: the server's stdin is closed (dropped with the task); let it drain.
        joined = &mut upstream => {
            joined.context("client relay task")??;
            downstream.await?;
        }
        // Server stopped talking: nothing left to relay to the client.
        done = &mut downstream => {
            upstream.abort();
            done?;
        }
    }

    let status = child.wait().await.context("waiting for server")?;
    if let Some(audit) = audit.as_ref() {
        audit.record(Event::Exit {
            code: status.code(),
        })?;
    }
    Ok(status.code().unwrap_or(1))
}

async fn pump(
    reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    dir: Direction,
    audit: Arc<Option<Audit>>,
    max: usize,
) -> anyhow::Result<()> {
    let mut reader = BufReader::new(reader);
    let mut frame = Vec::new();
    loop {
        frame.clear();
        // +1 so that a frame of exactly `max` bytes plus its newline still fits.
        let n = (&mut reader)
            .take(max as u64 + 1)
            .read_until(b'\n', &mut frame)
            .await?;
        if n == 0 {
            break;
        }
        if !frame.ends_with(b"\n") && n > max {
            // Fail closed: an oversized frame cannot be inspected, and skipping it would
            // desynchronize the stream.
            if let Some(audit) = audit.as_ref() {
                audit.record(Event::Rejected {
                    dir,
                    reason: format!("frame exceeds {max} bytes"),
                })?;
            }
            bail!("{dir:?}: frame exceeds {max} bytes");
        }
        let body = frame.strip_suffix(b"\n").unwrap_or(&frame);
        let body = body.strip_suffix(b"\r").unwrap_or(body);
        if body.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice::<Value>(body) {
            Ok(msg) => {
                if let Some(audit) = audit.as_ref() {
                    audit.record(Event::Message { dir, msg })?;
                }
                writer.write_all(&frame).await?;
                if !frame.ends_with(b"\n") {
                    writer.write_all(b"\n").await?;
                }
                writer.flush().await?;
            }
            Err(e) => {
                if let Some(audit) = audit.as_ref() {
                    audit.record(Event::Rejected {
                        dir,
                        reason: format!("invalid json: {e}"),
                    })?;
                }
            }
        }
    }
    writer.shutdown().await?;
    Ok(())
}
