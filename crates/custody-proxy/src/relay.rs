//! Stdio relay between an MCP client (our stdin/stdout) and a server subprocess.
//!
//! MCP stdio frames are newline-delimited JSON. Each frame is parsed, shown to the gateway,
//! logged, and then forwarded byte for byte, answered by the gateway, or dropped. A frame that
//! does not parse is logged and dropped: anything the gateway cannot inspect must not pass.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use custody_core::{Finding, Gateway, Verdict, pins::PinEvent};
use serde_json::Value;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, Stdout,
};
use tokio::process::{ChildStdin, Command};

use crate::audit::{Audit, Direction, Event};

#[derive(Debug)]
pub struct Config {
    pub command: Vec<String>,
    pub max_message_bytes: usize,
    /// Where pins are persisted when new tools are pinned.
    pub pins_path: Option<PathBuf>,
}

#[derive(Debug)]
struct Shared {
    gateway: Mutex<Gateway>,
    audit: Option<Audit>,
    client_out: tokio::sync::Mutex<Stdout>,
    pins_path: Option<PathBuf>,
    max: usize,
}

impl Shared {
    fn log(&self, event: Event) -> anyhow::Result<()> {
        if let Some(audit) = &self.audit {
            audit.record(event)?;
        }
        Ok(())
    }

    fn decide(&self, dir: Direction, msg: &Value) -> anyhow::Result<custody_core::Decision> {
        let mut gateway = self
            .gateway
            .lock()
            .map_err(|_| anyhow::anyhow!("gateway lock poisoned"))?;
        Ok(match dir {
            Direction::ClientToServer => gateway.client_frame(msg),
            Direction::ServerToClient => gateway.server_frame(msg),
        })
    }

    async fn to_client(&self, frame: &[u8]) -> anyhow::Result<()> {
        let mut out = self.client_out.lock().await;
        out.write_all(frame).await?;
        if !frame.ends_with(b"\n") {
            out.write_all(b"\n").await?;
        }
        out.flush().await?;
        Ok(())
    }

    fn save_pins(&self) -> anyhow::Result<()> {
        let Some(path) = &self.pins_path else {
            return Ok(());
        };
        let json = self
            .gateway
            .lock()
            .map_err(|_| anyhow::anyhow!("gateway lock poisoned"))?
            .pins()
            .to_json()?;
        // Write then rename, so a crash never leaves a truncated pin file.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// Runs until the server exits and returns its exit code.
pub async fn run(config: Config, gateway: Gateway, audit: Option<Audit>) -> anyhow::Result<i32> {
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

    let shared = Arc::new(Shared {
        gateway: Mutex::new(gateway),
        audit,
        client_out: tokio::sync::Mutex::new(tokio::io::stdout()),
        pins_path: config.pins_path,
        max: config.max_message_bytes,
    });

    let mut upstream = tokio::spawn(client_to_server(Arc::clone(&shared), child_in));
    let downstream = server_to_client(Arc::clone(&shared), child_out);
    tokio::pin!(downstream);

    tokio::select! {
        // Client finished: the server's stdin is closed with the task; let it drain.
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
    shared.log(Event::Exit {
        code: status.code(),
    })?;
    Ok(status.code().unwrap_or(1))
}

async fn client_to_server(shared: Arc<Shared>, mut server: ChildStdin) -> anyhow::Result<()> {
    let dir = Direction::ClientToServer;
    let mut frames = Frames::new(tokio::io::stdin(), shared.max);
    while let Some(frame) = next_frame(&shared, dir, &mut frames).await? {
        let Some(msg) = parse(&shared, dir, frame)? else {
            continue;
        };
        let decision = shared.decide(dir, &msg)?;
        shared.log(Event::Message { dir, msg })?;
        log_findings(&shared, decision.findings)?;
        match decision.verdict {
            Verdict::Forward => write_frame(&mut server, frame).await?,
            Verdict::Reply(reply) => {
                let bytes = serde_json::to_vec(&reply)?;
                shared.log(Event::Reply { msg: reply })?;
                shared.to_client(&bytes).await?;
            }
            Verdict::Drop => {}
        }
    }
    server.shutdown().await?;
    Ok(())
}

async fn server_to_client(
    shared: Arc<Shared>,
    server: impl AsyncRead + Unpin,
) -> anyhow::Result<()> {
    let dir = Direction::ServerToClient;
    let mut frames = Frames::new(server, shared.max);
    while let Some(frame) = next_frame(&shared, dir, &mut frames).await? {
        let Some(msg) = parse(&shared, dir, frame)? else {
            continue;
        };
        let decision = shared.decide(dir, &msg)?;
        shared.log(Event::Message { dir, msg })?;
        let pinned = decision.findings.iter().any(|f| {
            matches!(
                f,
                Finding::Pin {
                    event: PinEvent::Pinned { .. }
                }
            )
        });
        log_findings(&shared, decision.findings)?;
        if pinned {
            shared.save_pins()?;
        }
        match decision.verdict {
            Verdict::Forward => shared.to_client(frame).await?,
            // The gateway does not rewrite server frames yet.
            Verdict::Reply(_) | Verdict::Drop => {}
        }
    }
    Ok(())
}

async fn next_frame<'f, R: AsyncRead + Unpin>(
    shared: &Shared,
    dir: Direction,
    frames: &'f mut Frames<R>,
) -> anyhow::Result<Option<&'f [u8]>> {
    match frames.next().await {
        Ok(frame) => Ok(frame),
        Err(e) => {
            shared.log(Event::Rejected {
                dir,
                reason: e.to_string(),
            })?;
            Err(e.context(format!("{dir:?}")))
        }
    }
}

fn log_findings(shared: &Shared, findings: Vec<Finding>) -> anyhow::Result<()> {
    for finding in findings {
        shared.log(Event::Finding { finding })?;
    }
    Ok(())
}

/// Returns `None` for a frame that was rejected (and logged).
fn parse(shared: &Shared, dir: Direction, frame: &[u8]) -> anyhow::Result<Option<Value>> {
    let body = frame.strip_suffix(b"\n").unwrap_or(frame);
    let body = body.strip_suffix(b"\r").unwrap_or(body);
    match serde_json::from_slice(body) {
        Ok(msg) => Ok(Some(msg)),
        Err(e) => {
            shared.log(Event::Rejected {
                dir,
                reason: format!("invalid json: {e}"),
            })?;
            Ok(None)
        }
    }
}

async fn write_frame(writer: &mut (impl AsyncWrite + Unpin), frame: &[u8]) -> anyhow::Result<()> {
    writer.write_all(frame).await?;
    if !frame.ends_with(b"\n") {
        writer.write_all(b"\n").await?;
    }
    writer.flush().await?;
    Ok(())
}

/// Newline-delimited frames with a size cap. Blank lines are skipped.
struct Frames<R> {
    reader: BufReader<R>,
    buf: Vec<u8>,
    max: usize,
}

impl<R: AsyncRead + Unpin> Frames<R> {
    fn new(reader: R, max: usize) -> Self {
        Self {
            reader: BufReader::new(reader),
            buf: Vec::new(),
            max,
        }
    }

    async fn next(&mut self) -> anyhow::Result<Option<&[u8]>> {
        loop {
            self.buf.clear();
            // +1 so that a frame of exactly `max` bytes plus its newline still fits.
            let n = (&mut self.reader)
                .take(self.max as u64 + 1)
                .read_until(b'\n', &mut self.buf)
                .await?;
            if n == 0 {
                return Ok(None);
            }
            if !self.buf.ends_with(b"\n") && n > self.max {
                // Fail closed: an oversized frame cannot be inspected, and skipping it would
                // desynchronize the stream.
                bail!("frame exceeds {} bytes", self.max);
            }
            if !self.buf.iter().all(u8::is_ascii_whitespace) {
                return Ok(Some(&self.buf));
            }
        }
    }
}
