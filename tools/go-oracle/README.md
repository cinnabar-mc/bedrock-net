# Go batch oracle

This small helper emits synthetic compressed batches through Cinnabar's pinned
Gophertunnel codec. It uses no game assets, accounts or external servers.

From this directory, regenerate the Rust fixture:

```sh
go run . > ../../tests/fixtures/go_batches.rs
cargo fmt --all --manifest-path ../../Cargo.toml
```

The module pin identifies the behavior baseline. Update it deliberately when
reviewing upstream compatibility changes, then inspect any fixture differences.

The `cmd/login-check` helper verifies synthetic offline requests with the same
Go pin and returns a signed server handshake plus an independent P-384 key
derivation. It reads bounded fixture JSON from stdin and requires loopback
metadata, so no account credentials or external hosts are needed.

Build `go build -o ../../target/login-check.exe ./cmd/login-check` and set
`BEDROCK_NET_LOGIN_ORACLE` to that executable before running
`cargo test --locked -p bedrock-net --features login`.
