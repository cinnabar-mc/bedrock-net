# Release dependencies

Use a pinned Git revision until the packages required by your application have
compatible registry releases. Check each package manifest for its license and
publication settings; the probe is not published.

Before publishing a package with workspace path dependencies, publish its
prerequisites and verify the packaged archive against their registry releases.
The version on a path dependency must match the local package version. Transport
forks must contain the fixes required by this workspace; a package with a similar
name does not establish compatibility.

The workspace pins protocolgen, bedrock-services and transport dependencies in
[Cargo.toml](../Cargo.toml). Keep applications on a compatible dependency graph.
Preserve each package's declared license and its attribution files when packaging.
Each client and pack crate includes its own `LICENSE-MIT`; `bedrock-client` also
includes `LICENSE-AXOLOTL` and `LICENSE-MIT-gophertunnel`. Check these files with
`cargo package --list` before publishing. The root package includes `NOTICE` and
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md), which retain its Apache, BSD
and MIT third-party notices in one document.
