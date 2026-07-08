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

## Tag and push

After the release PR is merged to `main`, CI is green, and artifacts are
smoke-tested:

```sh
git checkout main
git pull origin main
git tag -a v0.1.7 -m "EtherFence v0.1.7: scan-only Linux/Windows discovery, path normalization, CI matrix, release packaging"
git push origin v0.1.7
```

Then create the GitHub release from the tag and attach the CI-built
`etherfence-linux-x86_64.tar.gz` and `etherfence-windows-x86_64.zip`:

```sh
gh release create v0.1.7 \
  --title "EtherFence v0.1.7" \
  --notes-file <(sed -n '/^## \[0.1.7\]/,/^## /p' CHANGELOG.md | sed '$d') \
  dist-ci/etherfence-linux-x86_64/etherfence-linux-x86_64.tar.gz \
  dist-ci/etherfence-windows-x86_64/etherfence-windows-x86_64.zip
```

## Release notes reminders

- Describe Windows support as conservative config discovery, not complete endpoint coverage.
- Mention that missing `USERPROFILE`, `APPDATA`, or `LOCALAPPDATA` is handled gracefully.
- Mention that path separators are normalized for stable evidence/fingerprints.
- Keep all examples generic, such as `/home/user/...` and `C:\Users\example\...`.
