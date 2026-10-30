#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn custody() -> Command {
    Command::new(env!("CARGO_BIN_EXE_custody"))
}

fn temp_path(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("custody-relay-{}-{name}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// Feeds `input` through `custody run -- cat` and returns what comes back.
fn echo_through(input: &[u8], extra: &[&str]) -> (Vec<u8>, i32) {
    let mut child = custody()
        .arg("run")
        .args(extra)
        .args(["--", "cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let mut out = Vec::new();
    child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
    (out, child.wait().unwrap().code().unwrap())
}

#[test]
fn forwards_frames_byte_for_byte() {
    // Key order and spacing must survive: the gateway forwards the original bytes.
    let input = b"{\"jsonrpc\":\"2.0\", \"method\":\"x\",\"id\":1}\n{\"b\":1,\"a\":[1.50,2]}\n";
    let (out, code) = echo_through(input, &[]);
    assert_eq!(code, 0);
    assert_eq!(out, input);
}

#[test]
fn drops_invalid_json_and_logs_it() {
    let log = temp_path("invalid");
    let input = b"{\"id\":1}\nnot json\n{\"id\":2}\n";
    let (out, code) = echo_through(input, &["--log", log.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert_eq!(out, b"{\"id\":1}\n{\"id\":2}\n");

    let text = std::fs::read_to_string(&log).unwrap();
    assert!(text.contains("\"kind\":\"rejected\""));
    let verify = custody()
        .args(["verify-log", log.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(verify.status.success());
    // 2 client frames, 1 rejection, 2 echoed frames, exit.
    assert_eq!(
        String::from_utf8_lossy(&verify.stdout).trim(),
        "ok: 6 records"
    );
}

#[test]
fn oversized_frame_stops_the_gateway() {
    let mut input = vec![b'"'; 100];
    input.extend_from_slice(b"\"\n");
    let (out, code) = echo_through(&input, &["--max-message-bytes", "16"]);
    assert_ne!(code, 0);
    assert!(out.is_empty());
}

#[test]
fn refuses_to_overwrite_a_log() {
    let log = temp_path("exists");
    std::fs::write(&log, "").unwrap();
    let (_, code) = echo_through(b"", &["--log", log.to_str().unwrap()]);
    assert_ne!(code, 0);
}

#[test]
fn passes_through_server_exit_code() {
    let status = custody()
        .args(["run", "--", "sh", "-c", "exit 3"])
        .stdin(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(3));
}
