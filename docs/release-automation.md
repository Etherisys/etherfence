# Release automation

`.github/workflows/release.yml` is the primary, safe release path for
EtherFence. It is a manual, explicit workflow: it only runs when a
maintainer dispatches it, and it never runs on `push`, `pull_request`, or a
schedule. It adds no runtime product behavior; it only automates the
verify-build-tag-release steps that were previously done by hand (see
`docs/release-checklist.md` for the fallback manual process).

## Why this exists

Manual releases (v0.2.2 through v0.2.4) repeatedly hit the same friction:

- local `main` diverging from `origin/main` after squash merges
- tags accidentally pointing at a PR branch commit instead of `main`
- picking the wrong CI run to pull artifacts from
- manually downloading and re-uploading Linux/Windows artifacts
- several manual checks that were easy to skip under time pressure

The release workflow removes the manual steps that were the actual source
of those mistakes while keeping the decision to release fully explicit.

## Triggering a release

From the Actions tab, or with the GitHub CLI:

```sh
gh workflow run release.yml --ref main -f version=0.2.5
```

The `version` input is required and must be the plain semver `X.Y.Z` used
in `Cargo.toml` (no `v` prefix, no pre-release suffix).

## What the workflow does

### 1. `validate` (read-only)

Fails closed on any of the following before anything else runs:

- the workflow was not dispatched from `refs/heads/main`
- `version` is not semver-like (`^[0-9]+\.[0-9]+\.[0-9]+$`)
- the `Cargo.toml` workspace version does not equal `version`
- `CHANGELOG.md` has no `## [<version>]` section
- a local or remote tag `v<version>` already exists
- a GitHub release `v<version>` already exists

### 2. `verify-and-build` (read-only, matrix: `ubuntu-latest` + `windows-latest`)

Runs, on both platforms, against the exact commit validated above:

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test`
- `cargo build`
- `git diff --check`
- `cargo build --release -p etherfence-cli`

Then packages and uploads:

- `etherfence-linux-x86_64.tar.gz` (Linux binary + `README.md` + `LICENSE`)
- `etherfence-linux-x86_64.tar.gz.sha256` (its SHA-256 checksum, in standard
  `sha256sum` format)
- `etherfence-windows-x86_64.zip` (Windows binary + `README.md` + `LICENSE`)
- `etherfence-windows-x86_64.zip.sha256` (its SHA-256 checksum, one line:
  hash then filename)

Unlike `ci.yml`, this job uses `fail-fast: true`: if either platform fails
verification or build, the release is not created.

### 3. `release` (`contents: write`)

Only this job can write to the repository. It:

- re-checks tag/release absence immediately before acting (closes the race
  between `validate` and this job)
- downloads both artifacts (and their `.sha256` checksum files) built in
  step 2 (never local artifacts)
- extracts release notes from the matching `CHANGELOG.md` section
- creates an annotated tag `v<version>` on the exact commit validated in
  step 1 and pushes it
- creates the GitHub release `v<version>` from that tag with the two
  archives and their two `.sha256` checksum files attached (four assets
  total)

See [`docs/install.md`](install.md#verifying-checksums) for how a user
verifies these checksum files against the downloaded archive on Linux and
Windows.

## Safety guarantees

- **Never mutates existing releases or tags.** Both are only ever created,
  never edited or replaced; existence is checked twice (`validate` and
  again immediately before tag/release creation).
- **Never force-pushes.** Tag creation is a plain `git push origin <tag>`
  of a brand-new tag.
- **Never releases from a non-`main` ref.** Checked before any other step
  runs.
- **Never uses local artifacts.** The `release` job only consumes artifacts
  produced by the `verify-and-build` job in the same run.
- **Least-privilege permissions.** The workflow default and the `validate`
  and `verify-and-build` jobs use `contents: read`; only the final
  `release` job elevates to `contents: write`, and only for the tag push
  and release creation steps.
- **Pinned third-party actions.** All non-`github/`-owned actions
  (`actions/checkout`, `dtolnay/rust-toolchain`, `actions/upload-artifact`,
  `actions/download-artifact`) are pinned by commit SHA with the tag noted
  in a comment, following the existing `ci.yml` convention. No `@v4`,
  `@main`, `@master`, or `@stable` action references are used.
- **Fails closed on ambiguity.** Any validation step that cannot cleanly
  confirm a precondition (ref, version format, version match, changelog
  section, tag absence, release absence) exits non-zero instead of
  proceeding.

## No new runtime behavior

This workflow only automates release packaging and publishing for the CLI
build artifacts already produced by `ci.yml`. It does not add daemon mode,
HTTP/SSE transport, shell hooks, network interception, terminal-command
scanning, wildcard/prefix/regex matching, or any new MCP proxy enforcement
semantics.
