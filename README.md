# bedrock-net

Native Rust networking foundations for Minecraft Bedrock, developed for
[Cinnabar](https://github.com/cinnabar-mc/cinnabar) and reusable by other clients.

The initial implementation provides a synchronous, runtime-independent batch
codec with raw DEFLATE and Snappy, explicit compression negotiation, bounded
decoding and ordered batch splitting. It accepts encoded packet bytes, including
their packet headers. Packet definitions and body serialization remain owned by
[protocolgen](https://github.com/cinnabar-mc/protocolgen).

```rust
use bedrock_net::{BatchCodec, BatchHeader, BatchLimits, DecodeOutcome};
use bytes::Bytes;

let codec = BatchCodec::new(BatchHeader::RakNet, BatchLimits::default());
let packet = Bytes::from_static(&[2, 0, 0, 0, 0]);
let batches = codec.encode(&[packet.clone()])?;
let DecodeOutcome::Packets(received) = codec.decode(batches[0].clone())? else {
    unreachable!("compression is not enabled");
};
assert_eq!(received, [packet]);
# Ok::<(), bedrock_net::BatchError>(())
```

After NetworkSettings, call `enable_compression` before processing subsequent
batches. Outgoing batches use the selected algorithm and threshold; incoming
batches use their declared algorithm. Unknown or invalid compressed payloads
produce `DecodeOutcome::Dropped`. The caller must count/log these outcomes and
continue reading. Framing, missing compression headers and size-limit violations
return errors. A malformed batch never exposes a partial packet list.

The default limits are library safety policy. Cinnabar may configure larger
batches for resource-pack transfers. Encoders split at both packet-count and
decoded-byte limits, preserve order, and produce no batch for an empty send.
Compression uses raw DEFLATE despite the protocol's Zlib naming.

This is an incremental implementation. Encryption, transport adapters, login,
services and real-server compatibility validation are still pending. The existing
Cinnabar Go backend remains the production implementation.

Run `cargo test --locked` for focused codec tests and `cargo fmt --all --check`
for formatting. See [NOTICE](NOTICE) for implementation references and licensing.
