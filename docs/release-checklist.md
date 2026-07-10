# EtherFence v1.0.0 Release Checklist

Status: pre-alpha overall; as of v1.0.0 the CLI surface and
`ef-mcp-policy/v0.1` schema are stable. Scan commands are scan-only; v0.2.x+
additionally ships the `etherfence mcp-proxy` stdio boundary proxy. This
checklist prepares Linux and Windows CLI artifacts without claiming
production readiness or security certification.

## Primary release path: the release workflow

The primary and preferred way to cut a release is the
manual `workflow_dispatch` GitHub Actions workflow in
`.github/workflows/release.yml`, documented in full in
`docs/release-automation.md`:

```sh
gh workflow run release.yml --ref main -f version=1.0.0
```

It validates release state, runs the same checks listed below on
`ubuntu-latest` and `windows-latest`, builds both artifacts, and creates the
tag and GitHub release automatically. It fails closed (refuses to proceed) if
the ref is not `main`, the version is not semver-like, `Cargo.toml` or
`CHANGELOG.md` don't match, or a matching tag/release already exists.

The rest of this checklist documents the fully manual fallback process and
the local checks a maintainer can run before dispatching the workflow.

## Scope guard

Confirm the release does not add:

- daemon mode
- shell hooks
- command interception
- terminal-command scanning
- network interception
- Tirith terminal detection duplication

Confirm the MCP proxy is described as a stable, locally-run stdio proxy (not
a production-readiness or security certification), fails closed on invalid
policy, supports stdio method/tool/path policy enforcement plus tracked
`tools/list` filtering, and is the only runtime component.

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
mkdir -p dist/etherfence-v1.0.0-linux-x86_64
cp target/release/etherfence dist/etherfence-v1.0.0-linux-x86_64/
tar -C dist -czf dist/etherfence-linux-x86_64.tar.gz etherfence-v1.0.0-linux-x86_64
(cd dist && sha256sum etherfence-linux-x86_64.tar.gz > etherfence-linux-x86_64.tar.gz.sha256)
```

Smoke check:

```sh
./target/release/etherfence scan --root tests/fixtures/home
./target/release/etherfence scan --root tests/fixtures/windows-home --policy-profile ci-runner --format json
./target/release/etherfence mcp-proxy --policy /nonexistent.toml -- true; test $? -eq 2
cargo test -p etherfence-cli optional_real_mcp_stdio_smoke_test -- --nocapture
```

## Windows release build

On Windows PowerShell:

```powershell
cargo build --release -p etherfence-cli
New-Item -ItemType Directory -Force -Path dist/etherfence-v1.0.0-windows-x86_64 | Out-Null
Copy-Item target/release/etherfence.exe dist/etherfence-v1.0.0-windows-x86_64/
Compress-Archive -Path dist/etherfence-v1.0.0-windows-x86_64 -DestinationPath dist/etherfence-windows-x86_64.zip -Force
$hash = (Get-FileHash dist/etherfence-windows-x86_64.zip -Algorithm SHA256).Hash.ToLower()
"$hash  etherfence-windows-x86_64.zip" | Set-Content -NoNewline -Path dist/etherfence-windows-x86_64.zip.sha256
```

Smoke check:

```powershell
.\target\release\etherfence.exe scan --root tests\fixtures\windows-home
.\target\release\etherfence.exe scan --root tests\fixtures\windows-home --policy-profile ci-runner --format json
```


## MCP compatibility matrix checks

For v1.0.0 and later, confirm:

- `docs/mcp-compatibility-matrix.md` exists and includes the fake MCP server row.
- `docs/mcp-proxy-operator-guide.md` exists, is linked from README.md and
  `docs/mcp-proxy.md`, and its referenced example paths exist.
- `docs/mcp-real-server-test-template.md` documents `ETHERFENCE_REAL_MCP_CMD` as JSON argv.
- Compatibility records do not claim daemon mode, HTTP/SSE transport, network interception, shell hooks, terminal-command scanning, wildcard/prefix/regex matching, or new enforcement semantics.
- Checked JSON client examples and example MCP proxy TOML policies are covered by tests.

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

## CI artifact smoke test

CI runs only on pushes and pull requests targeting `main`; pushing a tag does
not trigger an artifact build. Download artifacts from the relevant `main`
(or release PR) run:

```sh
gh run list --branch main --workflow ci --limit 5
gh run download <run-id> --dir dist-ci
tar -xzf dist-ci/etherfence-linux-x86_64/etherfence-linux-x86_64.tar.gz -C dist-ci
dist-ci/etherfence-v*-linux-x86_64/etherfence scan --root tests/fixtures/home
dist-ci/etherfence-v*-linux-x86_64/etherfence scan --root tests/fixtures/windows-home --policy-profile ci-runner --format json
```

Smoke-test `etherfence-windows-x86_64.zip` on a Windows machine (or document
that it was validated only by the `windows-latest` CI job).

## Tag and push (manual fallback)

Prefer dispatching `release.yml` (see above). Use this fully manual path only
if the automated workflow is unavailable.

After the release PR is merged to `main`, CI is green, and artifacts are
smoke-tested:

```sh
git checkout main
git pull origin main
git tag -a v1.0.0 -m "EtherFence v1.0.0: stable local-first MCP boundary release"
git push origin v1.0.0
```

Then create the GitHub release from the tag and attach the CI-built
`etherfence-linux-x86_64.tar.gz` and `etherfence-windows-x86_64.zip`:

```sh
gh release create v1.0.0 \
  --title "EtherFence v1.0.0" \
  --notes-file <(sed -n '/^## \[1.0.0\]/,/^## /p' CHANGELOG.md | sed '$d') \
  dist-ci/etherfence-linux-x86_64/etherfence-linux-x86_64.tar.gz \
  dist-ci/etherfence-linux-x86_64/etherfence-linux-x86_64.tar.gz.sha256 \
  dist-ci/etherfence-windows-x86_64/etherfence-windows-x86_64.zip \
  dist-ci/etherfence-windows-x86_64/etherfence-windows-x86_64.zip.sha256
```

Since v0.8.0, attach the `.sha256` checksum files alongside each archive so
release consumers can verify downloads (see
[`docs/install.md#verifying-checksums`](install.md#verifying-checksums)).
Generate them locally with the same commands shown in the Linux/Windows
release build steps above if the CI-built artifacts don't already include
them.

## Release notes reminders

- Describe the MCP proxy as a stable, locally-run stdio proxy — stable CLI
  surface and policy schema, not a production-readiness or security
  certification for any specific MCP server.
- Point to `docs/mcp-proxy-operator-guide.md` for how to wrap a real MCP
  server with the proxy.
- Describe Windows support as conservative config discovery, not complete endpoint coverage.
- Mention that missing `USERPROFILE`, `APPDATA`, or `LOCALAPPDATA` is handled gracefully.
- Mention that path separators are normalized for stable evidence/fingerprints.
- Keep all examples generic, such as `/home/user/...` and `C:\Users\example\...`.
