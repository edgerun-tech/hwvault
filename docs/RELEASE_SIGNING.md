# Release Signing & Reproducible Build Guide

This guide addresses production-readiness issue #3.

## Goals

- produce deterministic release artifacts for `openclaw-hwvault-resolver`
- publish checksums for verification
- support artifact signing in CI

## Deterministic build baseline

Use a pinned Rust toolchain and release profile:

```bash
rustup toolchain install stable
cargo build --release --bin openclaw-hwvault-resolver --locked
```

## Generate checksums

```bash
sha256sum target/release/openclaw-hwvault-resolver > openclaw-hwvault-resolver.sha256
```

## Verify checksums

```bash
sha256sum -c openclaw-hwvault-resolver.sha256
```

## CI release artifact flow

The repository includes a workflow that:

1. builds the resolver with `--locked`
2. emits a SHA256 checksum
3. uploads both binary and checksum as workflow artifacts

Workflow file:

- `.github/workflows/release-artifacts.yml`

## Signing recommendation

For production releases, sign checksums/artifacts with Sigstore Cosign (keyless or key-based):

```bash
cosign sign-blob --yes openclaw-hwvault-resolver.sha256
```

Publish:

- binary
- `.sha256`
- signature bundle/certificate (if used)

## Reproducibility notes

- Keep `Cargo.lock` committed and use `--locked`.
- Build in clean environment (container/runner) for release output.
- Avoid embedding nondeterministic metadata in release packaging steps.
