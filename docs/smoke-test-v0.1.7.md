# EtherFence v0.1.7 Smoke Test

Status: pre-alpha, scan-only. These smoke tests verify conservative Linux/Windows fixture scans and policy-profile behavior.

## Build

```sh
cargo build --release -p etherfence-cli
```

## Linux-style fixture scan

```sh
./target/release/etherfence scan --root tests/fixtures/home
```

Expected:

- command exits `0`
- report says `Status: pre-alpha-scan-only`
- report includes Linux-style `~/...` config paths
- report includes posture findings and remediation guidance

## Windows-style fixture scan

```sh
./target/release/etherfence scan --root tests/fixtures/windows-home --format json
```

Expected:

- command exits `0`
- JSON has `schema_version: ef-scan-report/v0.1.1`
- inventory includes `~/AppData/Roaming/Code/User/settings.json`
- evidence normalizes Windows path separators, for example `C:/Users/example/...`

## Built-in policy profile on Windows fixture

```sh
./target/release/etherfence scan \
  --root tests/fixtures/windows-home \
  --policy-profile ci-runner \
  --format json
```

Expected:

- command exits `0`
- JSON includes `policy.policy_name: ci-runner`
- JSON includes `policy.policy_source: built-in-profile`
- policy findings appear as ordinary findings and remain scan-only

## CI gate behavior

```sh
./target/release/etherfence scan \
  --root tests/fixtures/windows-home \
  --policy-profile ci-runner \
  --fail-on high
```

Expected:

- command exits `2` when high-severity posture or policy findings are present
- no runtime enforcement occurs

## Non-goals to re-check

The smoke test should not require or demonstrate daemon mode, runtime blocking, MCP proxying, shell hooks, command interception, terminal-command scanning, network interception, or Tirith terminal detection duplication.
