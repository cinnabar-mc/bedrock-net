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
