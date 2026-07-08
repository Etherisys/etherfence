# EtherFence v0.1.7 Release Checklist

Status: pre-alpha, scan-only. This checklist prepares Linux and Windows CLI artifacts without claiming runtime enforcement or production readiness.

## Scope guard

Confirm the release does not add:

- runtime blocking
- daemon mode
- MCP proxying
- shell hooks
- command interception
- terminal-command scanning
- network interception
- Tirith terminal detection duplication

## Required local checks

Run from the repository root:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build
git diff --check
```

## Linux release build

On Linux:

```sh
cargo build --release -p etherfence-cli
mkdir -p dist/etherfence-v0.1.7-linux-x86_64
cp target/release/etherfence dist/etherfence-v0.1.7-linux-x86_64/
tar -C dist -czf dist/etherfence-linux-x86_64.tar.gz etherfence-v0.1.7-linux-x86_64
```

Smoke check:

```sh
./target/release/etherfence scan --root tests/fixtures/home
./target/release/etherfence scan --root tests/fixtures/windows-home --policy-profile ci-runner --format json
```

## Windows release build

On Windows PowerShell:

```powershell
cargo build --release -p etherfence-cli
New-Item -ItemType Directory -Force -Path dist/etherfence-v0.1.7-windows-x86_64 | Out-Null
Copy-Item target/release/etherfence.exe dist/etherfence-v0.1.7-windows-x86_64/
Compress-Archive -Path dist/etherfence-v0.1.7-windows-x86_64 -DestinationPath dist/etherfence-windows-x86_64.zip -Force
```

Smoke check:

```powershell
.\target\release\etherfence.exe scan --root tests\fixtures\windows-home
.\target\release\etherfence.exe scan --root tests\fixtures\windows-home --policy-profile ci-runner --format json
```

## GitHub Actions

The CI workflow runs on:

- `ubuntu-latest`
- `windows-latest`

Each matrix job runs:

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test`
- `cargo build`
- `cargo build --release -p etherfence-cli`

The workflow uploads:

- `etherfence-linux-x86_64.tar.gz`
- `etherfence-windows-x86_64.zip`

## Release notes reminders

- Describe Windows support as conservative config discovery, not complete endpoint coverage.
- Mention that missing `USERPROFILE`, `APPDATA`, or `LOCALAPPDATA` is handled gracefully.
- Mention that path separators are normalized for stable evidence/fingerprints.
- Keep all examples generic, such as `/home/user/...` and `C:\Users\example\...`.
