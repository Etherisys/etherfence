# Install

Status: **v1.5.0 — production-ready for controlled local-first deployments
of its defined scope** (`scan`, `mcp-policy`, and the stdio `mcp-proxy`
boundary) with a stable CLI and policy schema — not a universal
certification for every MCP server, MCP client, or deployment environment,
same as the rest of EtherFence (see the
[README status line](../README.md)). Installing EtherFence gives you a
single local CLI binary; nothing here installs a daemon, service, or
background agent.

There are three ways to get `etherfence`:

1. Download a release artifact (Linux or Windows) — fastest, no Rust toolchain needed.
2. Build from source with `cargo build --release`.
3. Install directly from a local checkout with `cargo install --path`.

## 1. Linux: install from a release artifact

Releases are cut manually (see [`docs/release-automation.md`](release-automation.md))
and published on the repository's
[GitHub Releases](https://github.com/Etherisys-id/etherfence/releases) page.
Each release attaches:

- `etherfence-linux-x86_64.tar.gz`
- `etherfence-linux-x86_64.tar.gz.sha256`

Download both files for the release you want, then:

```sh
# Verify the checksum before extracting anything.
sha256sum -c etherfence-linux-x86_64.tar.gz.sha256

# Extract. The archive contains a versioned directory, e.g.
# etherfence-v1.5.0-linux-x86_64/{etherfence,README.md,LICENSE}.
tar -xzf etherfence-linux-x86_64.tar.gz

# Run it in place...
./etherfence-v*-linux-x86_64/etherfence --version

# ...or put it on PATH.
install -m 0755 etherfence-v*-linux-x86_64/etherfence ~/.local/bin/etherfence
etherfence --version
```

If `sha256sum -c` reports anything other than `OK`, do not run the binary —
re-download it or see [Verifying checksums](#verifying-checksums) below.

## 2. Windows: install from a release artifact

Each release attaches:

- `etherfence-windows-x86_64.zip`
- `etherfence-windows-x86_64.zip.sha256`

Download both files, then in PowerShell:

```powershell
# Verify the checksum before extracting anything.
$expected = (Get-Content etherfence-windows-x86_64.zip.sha256).Split(" ")[0]
$actual = (Get-FileHash etherfence-windows-x86_64.zip -Algorithm SHA256).Hash
if ($actual -ne $expected.ToUpper()) { throw "checksum mismatch" }

# Extract. The archive contains a versioned directory, e.g.
# etherfence-v1.5.0-windows-x86_64\{etherfence.exe,README.md,LICENSE}.
Expand-Archive etherfence-windows-x86_64.zip -DestinationPath .

# Run it in place...
.\etherfence-v*-windows-x86_64\etherfence.exe --version
```

Add the extracted directory to your `PATH`, or copy `etherfence.exe`
somewhere already on it, to run `etherfence` from any shell.

## 3. Build from source

Requires a stable Rust toolchain ([rustup.rs](https://rustup.rs)).

```sh
git clone https://github.com/Etherisys-id/etherfence.git
cd etherfence
cargo build --release -p etherfence-cli
./target/release/etherfence --version
```

On Windows, the built binary is `target\release\etherfence.exe`.

## 4. Local source install with `cargo install --path`

From a checkout of this repository:

```sh
cargo install --path crates/etherfence-cli --bin etherfence
etherfence --version
```

`--bin etherfence` is intentional: `crates/etherfence-cli` also builds a
`fake-mcp-server` test fixture binary (used only by the integration test
suite), and this flag keeps it out of your `~/.cargo/bin`.

## Verifying the install

```sh
etherfence --version
```

should print `etherfence <version>` matching the release or checkout you
installed (`1.5.0` for this release).

## Run your first scan

```sh
# Scan your real local AI-agent/MCP configuration.
etherfence scan

# Or scan a specific directory (useful for a fresh checkout or CI).
etherfence scan --root /path/to/project
```

See the [README quickstart](../README.md#quickstart) for the full first-run
walkthrough, including validating and dry-running an MCP policy.

## Release artifacts

| Artifact | Platform | Contents |
| --- | --- | --- |
| `etherfence-linux-x86_64.tar.gz` | Linux x86_64 | `etherfence-v<version>-linux-x86_64/` containing `etherfence`, `README.md`, `LICENSE` |
| `etherfence-windows-x86_64.zip` | Windows x86_64 | `etherfence-v<version>-windows-x86_64\` containing `etherfence.exe`, `README.md`, `LICENSE` |

Both artifacts, plus a matching `.sha256` file for each, are built and
attached by the manual release workflow described in
[`docs/release-automation.md`](release-automation.md). No other platforms or
architectures are currently published.

## Verifying checksums

Every release artifact has a matching `<artifact>.sha256` file containing a
single line: the SHA-256 hash followed by the filename, in the standard
`sha256sum` format.

Linux/macOS:

```sh
sha256sum -c etherfence-linux-x86_64.tar.gz.sha256
```

Windows PowerShell:

```powershell
$expected = (Get-Content etherfence-windows-x86_64.zip.sha256).Split(" ")[0]
$actual = (Get-FileHash etherfence-windows-x86_64.zip -Algorithm SHA256).Hash
if ($actual -eq $expected.ToUpper()) { "OK" } else { "MISMATCH" }
```

If you only have the archive and not the `.sha256` file (for example, an
older release published before checksum files were added), compute the hash
yourself and compare it against the value shown on the GitHub release page:

```sh
sha256sum etherfence-linux-x86_64.tar.gz
```

```powershell
Get-FileHash etherfence-windows-x86_64.zip -Algorithm SHA256
```

## Smoke-test checklist

Run through this checklist to confirm an installed binary works end to end.
It exercises `scan`, `policy`, and `mcp-policy` — all local, read-only, or
serverless — plus an optional `mcp-proxy` fail-closed check. A **release
artifact** only ships the binary, `README.md`, and `LICENSE` (no example
policies), so the commands below use `mcp-policy init` to generate a policy
and an inline JSON request instead of referencing checked-in example files.
If you built from a repository checkout instead, you can substitute any of
the checked-in files under `examples/policies/` or `docs/examples/ci/`.

### Linux artifact smoke test

```sh
./etherfence --version

# Point --root at any directory; a temp dir with no agent configs is fine.
./etherfence scan --root "$(mktemp -d)"

./etherfence policy list

./etherfence mcp-policy init --profile minimal --output /tmp/ef-smoke-policy.toml
./etherfence mcp-policy validate /tmp/ef-smoke-policy.toml

./etherfence mcp-policy check \
  --policy /tmp/ef-smoke-policy.toml \
  --request '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# Optional: confirm mcp-proxy fails closed on a missing policy (exit 2,
# no process started).
./etherfence mcp-proxy --policy /nonexistent.toml -- true
echo "exit code: $?"   # expect 2
```

### Windows artifact smoke test

```powershell
.\etherfence.exe --version

$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ([System.Guid]::NewGuid()))
.\etherfence.exe scan --root $tmp.FullName

.\etherfence.exe policy list

.\etherfence.exe mcp-policy init --profile minimal --output "$env:TEMP\ef-smoke-policy.toml"
.\etherfence.exe mcp-policy validate "$env:TEMP\ef-smoke-policy.toml"

.\etherfence.exe mcp-policy check `
  --policy "$env:TEMP\ef-smoke-policy.toml" `
  --request '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# Optional: confirm mcp-proxy fails closed on a missing policy (exit 2).
.\etherfence.exe mcp-proxy --policy C:\nonexistent.toml -- cmd /c exit 0
echo "exit code: $LASTEXITCODE"   # expect 2
```

None of these commands write outside the paths you pass them, start an MCP
server, or require network access.

### Optional: fake-MCP-server proxy smoke test (repository checkout only)

If you built from a repository checkout, `cargo build` also produces a
`fake-mcp-server` test-fixture binary you can wrap with `mcp-proxy` for a
real end-to-end proxy smoke test:

```sh
cargo run -p etherfence-cli --bin etherfence -- mcp-policy init \
  --profile minimal --output /tmp/ef-smoke-policy.toml
cargo run -p etherfence-cli --bin etherfence -- mcp-proxy \
  --policy /tmp/ef-smoke-policy.toml \
  -- cargo run -p etherfence-cli --bin fake-mcp-server
```

This is a development convenience, not something release-artifact users can
do without also building from source.
