# Release dependencies

Use a pinned Git revision until the packages required by your application have
compatible registry releases. Check each package manifest for its license and
publication settings; the probe is not published.

Before publishing a package with workspace path dependencies, publish its
prerequisites and verify the packaged archive against their registry releases.
The version on a path dependency must match the local package version. Transport
forks must contain the fixes required by this workspace; a package with a similar
name does not establish compatibility. The `raknet` crates.io name belongs to
another repository, so its publication name or ownership must be resolved before
adding a registry fallback.

The workspace pins protocolgen, bedrock-services and transport dependencies in
[Cargo.toml](../Cargo.toml). Keep applications on a compatible dependency graph.
Preserve each package's declared license and its attribution files when packaging.
