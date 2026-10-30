mod audit;
mod relay;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};

use custody_core::{Gateway, Pins, Policy};

use crate::audit::Audit;

#[derive(Debug, Parser)]
#[command(
    name = "custody",
    version,
    about = "MCP gateway with information-flow control"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run an MCP stdio server behind the gateway.
    Run {
        /// Write a hash-chained audit log here. The file must not exist.
        #[arg(long)]
        log: Option<PathBuf>,
        /// TOML policy. Without one every call is allowed, but tool pins are still enforced.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Persist tool pins here, so a definition changed between runs is caught too.
        #[arg(long)]
        pins: Option<PathBuf>,
        /// Largest accepted frame in bytes; a bigger one stops the gateway.
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        max_message_bytes: usize,
        /// Server command, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Check that an audit log has not been altered.
    VerifyLog { path: PathBuf },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(e) => {
            eprintln!("custody: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<i32> {
    match cli.cmd {
        Cmd::Run {
            log,
            policy,
            pins,
            max_message_bytes,
            command,
        } => {
            let audit = log
                .map(|p| Audit::create(&p).with_context(|| format!("opening {}", p.display())))
                .transpose()?;
            let policy = match policy {
                Some(p) => Policy::from_toml(&read(&p)?)
                    .with_context(|| format!("parsing {}", p.display()))?,
                None => Policy::default(),
            };
            let loaded_pins = match &pins {
                Some(p) if p.exists() => Pins::from_json(&read(p)?)
                    .with_context(|| format!("parsing {}", p.display()))?,
                _ => Pins::default(),
            };
            let gateway = Gateway::new(policy, loaded_pins);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let result = runtime.block_on(relay::run(
                relay::Config {
                    command,
                    max_message_bytes,
                    pins_path: pins,
                },
                gateway,
                audit,
            ));
            // Stdin is read on a blocking thread that may never return if the client keeps it
            // open after the server is gone; do not wait for it.
            runtime.shutdown_background();
            result
        }
        Cmd::VerifyLog { path } => {
            let n = audit::verify(&path)?;
            println!("ok: {n} records");
            Ok(0)
        }
    }
}

fn read(path: &std::path::Path) -> anyhow::Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}
