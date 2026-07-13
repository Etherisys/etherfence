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
        "oversized-response" => {
            // Read one line (so the client's first write succeeds), then
            // respond with a single frame far larger than the proxy's frame
            // cap and without a terminating newline, then keep reading
            // stdin like a normal, still-running MCP server that never saw
            // EOF. Used to prove the proxy detects an oversized
            // server-to-client frame and shuts itself down instead of
            // hanging while a client that never sends anything further
            // would otherwise leave it blocked forever.
            let stdin = std::io::stdin().lock();
            let mut lines = stdin.lines();
            if let Some(line) = lines.next() {
                let _ = line.expect("read fake server stdin");
            }
            let mut stdout = std::io::stdout().lock();
            let oversized = vec![b'x'; 8 * 1024 * 1024 + 1024];
            let _ = stdout.write_all(&oversized);
            let _ = stdout.flush();
            for line in lines {
                let _ = line;
            }
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
        if message.get("method").is_none() {
            // The proxy can send JSON-RPC error responses back to this fake
            // server when it denies server→client requests. Log those inbound
            // responses above, but do not answer responses with more responses.
            continue;
        }
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
            Some("tools/list")
                if message.pointer("/params/fixture").and_then(Value::as_str) == Some("rich") =>
            {
                // Realistic nested inputSchema shape (object properties with a
                // nested object and an array-of-strings property), similar to
                // filesystem/search-style real MCP servers. Used to prove
                // tools/list filtering preserves an allowed tool's full schema
                // structure unchanged rather than only its name.
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "tools": [
                            {
                                "name": "compat.rich_tool",
                                "description": "Tool with a realistic nested inputSchema",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "path": {"type": "string"},
                                        "options": {
                                            "type": "object",
                                            "properties": {
                                                "recursive": {"type": "boolean"},
                                                "filters": {
                                                    "type": "array",
                                                    "items": {"type": "string"}
                                                }
                                            }
                                        }
                                    },
                                    "required": ["path"]
                                }
                            },
                            {"name": "compat.denied", "description": "Denied compatibility fixture tool", "inputSchema": {"type":"object","properties": {}}}
                        ]
                    },
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
            Some("fixture/server_sampling") => json!({
                "jsonrpc": "2.0",
                "id": "server-sampling-1",
                "method": "sampling/createMessage",
                "params": {"messages": [{"role": "user", "content": "secret prompt text from server"}]},
            }),
            Some("fixture/server_roots") => json!({
                "jsonrpc": "2.0",
                "id": "server-roots-1",
                "method": "roots/list",
                "params": {"cursor": "secret cursor"},
            }),
            Some("fixture/server_elicitation_notification") => json!({
                "jsonrpc": "2.0",
                "method": "elicitation/create",
                "params": {"message": "secret notification body"},
            }),
            Some("fixture/server_batch") => json!([
                {"jsonrpc": "2.0", "id": "server-batch-1", "method": "roots/list", "params": {}}
            ]),

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
            Some("resources/list")
                if message.pointer("/params/fixture").and_then(Value::as_str) == Some("rich") =>
            {
                // Realistic resources/list shape (uri/name/mimeType entries),
                // similar to a filesystem- or notes-style MCP resource
                // listing, rather than the bare echo used elsewhere.
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "resources": [
                            {"uri": "file:///project/README.md", "name": "README", "mimeType": "text/markdown"},
                            {"uri": "file:///project/src/lib.rs", "name": "lib.rs", "mimeType": "text/x-rust"}
                        ]
                    },
                })
            }
            Some("resources/read")
                if message.pointer("/params/fixture").and_then(Value::as_str) == Some("rich") =>
            {
                // Realistic resources/read content shape (a contents array
                // with uri/mimeType/text), echoing the requested uri back so
                // the test can assert it was forwarded unchanged.
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "contents": [
                            {
                                "uri": message.pointer("/params/uri").cloned().unwrap_or(json!(null)),
                                "mimeType": "text/plain",
                                "text": "fixture resource contents"
                            }
                        ]
                    },
                })
            }
            // v0.3.0: respond to non-tool methods so integration tests can
            // verify that allowed methods reach the server and denied ones
            // do not. The response echoes the method so tests can assert
            // forwarding without needing a real MCP server.
            Some("resources/list")
            | Some("resources/read")
            | Some("prompts/list")
            | Some("prompts/get")
            | Some("completion/complete")
            | Some("roots/list")
            | Some("sampling/createMessage")
            | Some("ping") => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "echo_method": message.get("method"),
                },
            }),
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
