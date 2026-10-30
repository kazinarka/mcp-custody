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

#[test]
fn denied_call_is_answered_by_the_gateway() {
    let policy = temp_path("policy.toml");
    std::fs::write(&policy, "default = \"deny\"\n[tools.allowed]\n").unwrap();
    let meta = r#""_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}"#;
    let allowed = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"allowed",{meta}}}}}"#
    );
    let denied = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"other",{meta}}}}}"#
    );
    let input = format!("{allowed}\n{denied}\n");
    let (out, code) = echo_through(input.as_bytes(), &["--policy", policy.to_str().unwrap()]);
    assert_eq!(code, 0);

    // `cat` echoes what reached it, so the allowed call comes back verbatim and the denied one
    // is replaced by the gateway's tool error.
    let lines: Vec<serde_json::Value> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    let (echo, reply) = if lines[0]["id"] == 1 {
        (&lines[0], &lines[1])
    } else {
        (&lines[1], &lines[0])
    };
    assert_eq!(echo["method"], "tools/call");
    assert_eq!(reply["id"], 2);
    assert_eq!(reply["result"]["isError"], true);
    assert_eq!(reply["result"]["resultType"], "complete");
}

#[test]
fn pins_are_written_to_disk() {
    let pins = temp_path("pins.json");
    // `cat` turns the request into its own "response", which is enough to exercise pinning:
    // the gateway matches the echoed id to the pending tools/list.
    let list = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","result":{"tools":[{"name":"t","description":"d"}]}}"#;
    let (_, code) = echo_through(
        format!("{list}\n").as_bytes(),
        &["--pins", pins.to_str().unwrap()],
    );
    assert_eq!(code, 0);
    let saved = std::fs::read_to_string(&pins).unwrap();
    assert!(saved.contains("\"t\""));
}
