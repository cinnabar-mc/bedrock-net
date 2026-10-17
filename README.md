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

`encryption::BatchEncryptor` and `BatchDecryptor` own independent continuous
AES-256-CTR streams and checksum counters. They take the session key derived by
the handshake. Encrypt the compressed body after removing any transport marker;
decrypt and verify before decompressing. Retain outgoing ciphertext in send order,
and bound incoming wire bytes before decryption. Integrity failures invalidate the
direction. A compression drop still consumes the encrypted batch's stream state.
Key exchange and authentication are separate, pending work.

Enable the `raknet` feature for `raknet::RakNetConnection`, a Tokio driver over a
pinned [bedrock-crustaceans/raknet](https://github.com/bedrock-crustaceans/raknet)
protocol engine. One connection owns its socket and protocol state and spawns no
background tasks. Queue complete messages with `queue_send`, then keep `recv`
polled in the session network loop to service acknowledgements and timers. `flush`
sends immediately available datagrams. Cancelling these waits retains pending
state; dropping a dial or connection releases its socket. Transport messages
retain their batch marker. Receive queue capacities and handshake/close deadlines
are explicit options. `wait_send_capacity` services ACKs when the outgoing byte
budget is full, retaining inbound messages for the next `recv`. Complete earlier
messages drain before terminal errors.

The minimum Rust version is 1.90, required by the pinned transport dependency.
For Go transport interoperability checks, build the loopback-only helper under
`tools/raknet-peer` and set `BEDROCK_NET_RAKNET_PEER` to that executable before
running `cargo test --locked -p bedrock-net --features raknet`.

This is an incremental implementation. NetherNet, login, services and
real-server compatibility validation are still pending. The existing Cinnabar Go
backend remains the production implementation.

Run `cargo test --locked` for focused codec tests and `cargo fmt --all --check`
for formatting. See [NOTICE](NOTICE) for implementation references and licensing.
