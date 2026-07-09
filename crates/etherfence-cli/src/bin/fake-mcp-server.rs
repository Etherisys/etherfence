//! Test-only fake MCP stdio server used by the `mcp-proxy` integration
//! tests. It echoes back the method and tool name of each request so tests
//! can prove which messages were (or were not) forwarded through the proxy.
//! It is not an MCP server implementation and is never packaged in releases.

use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::{BufRead, Write};

fn main() {
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
        let response = json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "echo_method": message.get("method"),
                "echo_tool": message.pointer("/params/name"),
            },
        });
        writeln!(stdout, "{response}").expect("write fake server stdout");
        stdout.flush().expect("flush fake server stdout");
    }
}
