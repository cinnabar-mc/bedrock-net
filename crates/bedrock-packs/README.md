# bedrock-packs

Resource-pack JSONC parsing and archive handoffs for Minecraft Bedrock applications.
Use it to read pack documents or pass downloaded archives to your pack loader.

This crate performs no filesystem, HTTP, packet or rendering I/O and needs no
async runtime. Your application validates archives and manifests, stores them and
applies their contents. For network transfer, use
[`bedrock-client`](https://github.com/cinnabar-mc/bedrock-net/blob/dev/crates/bedrock-client/README.md) or its
[Tokio adapter](https://github.com/cinnabar-mc/bedrock-net/blob/dev/crates/bedrock-client-tokio/README.md).

## Install

```sh
cargo add --git https://github.com/cinnabar-mc/bedrock-net --branch dev bedrock-packs
```

## Parse a pack document

`parse_jsonc` accepts a complete JSON document with comments, a UTF-8 BOM and
trailing commas. Choose the deserialized type to match the document:

```rust
use std::collections::BTreeMap;
use bedrock_packs::jsonc::parse_jsonc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let document = br#"{
        // A small language configuration.
        "language": "en_US",
    }"#;
    let values: BTreeMap<String, String> = parse_jsonc(document)?;
    assert_eq!(values["language"], "en_US");
    Ok(())
}
```

`decode_text` preserves valid UTF-8 spans and maps invalid bytes to Latin-1
characters. `parse_jsonc_lenient` reads only the first value, allowing trailing
data, hash comments and an unfinished trailing comment. Use `normalize_jsonc`
when you need strict JSON bytes rather than a deserialized value.

## Consume downloaded archives

Client pack negotiation returns a `ResourcePackHandoff`. Take relay-added packs
separately, then consume the server archives in their selected application order:

```rust
use bedrock_packs::ResourcePackHandoff;

fn consume(mut handoff: ResourcePackHandoff) {
    let required = handoff.required();
    let relay_packs = handoff.take_relay_packs();
    let server_packs = handoff.into_archives();
    // Validate and apply the archives using the application's pack loader.
    // Keep relay ordering separate from the server's `required` policy.
    let _ = (required, relay_packs, server_packs);
}
```

Each `ResourcePackArchive` retains compressed bytes, pack ID, advertised version,
selected subpack and an optional content key. Version and subpack fields retain
raw bytes. Content keys are zeroized on drop and excluded from diagnostic
formatting; borrow one explicitly with `content_key.expose()` when needed.
Constructors retain supplied data without validating an archive or its manifest.

## License

This crate is [MIT licensed](https://github.com/cinnabar-mc/bedrock-net/blob/dev/crates/bedrock-packs/LICENSE-MIT).
