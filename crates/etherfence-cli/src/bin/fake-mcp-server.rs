//! Test-only fake MCP stdio server used by the `mcp-proxy` integration
//! tests. It implements a small deterministic MCP-like stdio fixture so tests
//! can exercise realistic initialize/tools/list/tools/call flows while proving
//! which messages were (or were not) forwarded through the proxy.
//! It is not a production MCP server implementation and is never packaged in
//! releases.

use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::{BufRead, Write};

fn main() {
    let mode = std::env::var("FAKE_MCP_SERVER_MODE").unwrap_or_default();
    match mode.as_str() {
        "immediate-exit" => {
            // Simulate a child MCP server that exits before producing any
            // output and without reading its stdin. The proxy must detect the
            // closed stdout and exit with the child's code.
            std::process::exit(0);
        }
        "read-one-then-drop" => {
            // Read a single line (so the client's first write succeeds), then
            // close stdout and exit without responding. Used to exercise the
            // proxy's behavior when the child drops mid-handshake.
            let stdin = std::io::stdin().lock();
            let mut lines = stdin.lines();
            if let Some(line) = lines.next() {
                let line = line.expect("read fake server stdin");
                if let Some(log) = std::env::var_os("FAKE_MCP_SERVER_LOG") {
                    let mut log = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(log)
                        .expect("open fake server receive log");
                    writeln!(log, "{line}").expect("write fake server receive log");
                }
            }
            std::process::exit(0);
        }
        _ => {}
    }

    let mut received_log = std::env::var_os("FAKE_MCP_SERVER_LOG").map(|path| {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open fake server receive log")
    });
    let stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lines() {
        let line = line.expect("read fake server stdin");
        if let Some(log) = received_log.as_mut() {
            writeln!(log, "{line}").expect("write fake server receive log");
        }
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let Some(id) = message.get("id").filter(|id| !id.is_null()) else {
            continue;
        };
        let response = match message.get("method").and_then(Value::as_str) {
            Some("initialize") => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": message
                        .pointer("/params/protocolVersion")
                        .cloned()
                        .unwrap_or_else(|| json!("2025-03-26")),
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "etherfence-compat-fixture", "version": "0.1.0"},
                    "echo_method": "initialize"
                }
            }),
            Some("tools/list")
                if message.pointer("/params/fixture").and_then(Value::as_str) == Some("error") =>
            {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32603, "message": "fixture tools/list error"},
                })
            }
            Some("tools/list")
                if message.pointer("/params/fixture").and_then(Value::as_str) == Some("weird") =>
            {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {"tools": "not-an-array"},
                })
            }
            Some("tools/list") => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {"name": "compat.allowed", "description": "Allowed compatibility fixture tool", "inputSchema": {"type":"object","properties": {}}},
                        {"name": "compat.denied", "description": "Denied compatibility fixture tool", "inputSchema": {"type":"object","properties": {}}},
                        {"name": "compat.server_error", "description": "Allowed tool that returns a server error", "inputSchema": {"type":"object","properties": {}}},
                        {"name": "github.list_repos", "description": "List repositories"},
                        {"name": "filesystem.read", "description": "Read a file"},
                        {"name": "filesystem.read_secret", "description": "Secret-bearing schema must not be audited"},
                        {"name": "shell.run", "description": "Run a command"},
                        {"name": "browser.open", "description": "Open a browser"},
                        {"description": "Malformed tool entry with no name"}
                    ]
                },
            }),
            Some("tools/list/weird") => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"tools": "not-an-array"},
            }),

            Some("tools/call")
                if message.pointer("/params/name").and_then(Value::as_str)
                    == Some("compat.server_error") =>
            {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32042, "message": "fixture tool failed", "data": {"fixture": true}},
                })
            }
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "echo_method": message.get("method"),
                    "echo_tool": message.pointer("/params/name"),
                },
            }),
        };
        writeln!(stdout, "{response}").expect("write fake server stdout");
        stdout.flush().expect("flush fake server stdout");
    }
}
