# bedrock-net

Reusable native Rust building blocks for Minecraft Bedrock connections. The
workspace covers batch framing, Login and key exchange, client resource-pack
negotiation, and startup prerequisites. It is developed for
[Cinnabar](https://github.com/cinnabar-mc/cinnabar), with application policy and
runtime integration kept outside the pure protocol owners.

## Choose a layer

| Crate | Responsibility |
| --- | --- |
| [`bedrock-net`](src/lib.rs) | Encoded packet batches, compression, directional ciphers and optional Login/transport helpers. |
| [`bedrock-client`](crates/bedrock-client) | Caller-driven generated-packet client negotiation, pack transfer, startup and accepting Login. |
| [`bedrock-packs`](crates/bedrock-packs) | Pack text decoding, owned archive handoffs and content-key lifetime. |
| [`bedrock-probe`](examples/client) | Standalone settings/offline-Login probe showing concrete transport integration. |

[protocolgen](https://github.com/cinnabar-mc/protocolgen) owns the version-specific
packet schemas and serializers. [bedrock-services](https://github.com/cinnabar-mc/bedrock-services)
owns account authentication and service traffic. This workspace consumes their
outputs; applications select accounts, authorize world/session joins, acquire
credentials and decide retry, cache, rendering and ongoing-play policy.

The three library crates are the default workspace members. They create no
runtime. The byte codec, Login helpers, pack owners and generated-packet protocol
owners perform no socket, HTTP, filesystem or clock I/O. Optional transport edges
are described below.

## Batch codec

Pass encoded packets, including their packet headers. The codec adds batch
framing, splits at the configured byte/packet limits and preserves wire order.
It leaves packet-body interpretation to the generated codec.

```rust
use bedrock_net::{BatchCodec, BatchHeader, BatchLimits, DecodeOutcome};
use bytes::Bytes;

let plain = BatchCodec::new(BatchHeader::RakNet, BatchLimits::default());
let packet = Bytes::from_static(&[0x02, 0, 0, 0, 0]);
let batches = plain.encode(std::slice::from_ref(&packet))?;
match plain.decode(batches[0].clone())? {
    DecodeOutcome::Packets { packets, .. } => assert_eq!(packets, [packet]),
    DecodeOutcome::Dropped(reason) => panic!("unexpected compression drop: {reason}"),
}
# Ok::<(), bedrock_net::BatchError>(())
```

After actual NetworkSettings, consume `plain.negotiate(settings)` to obtain a
`BatchCodec<Negotiated>`. That owner cannot renegotiate or reset compression.
Raw DEFLATE and Snappy are supported; the protocol's Zlib name means raw DEFLATE.
Incoming negotiated batches select their declared algorithm independently of the
outgoing threshold.

`DecodeOutcome::Dropped` means count/log the compression failure and continue.
Framing and size violations return `BatchError`; a malformed batch never exposes
partial packets. Empty incoming entries are skipped and counted. Limits are
explicit library policy, adjustable for an application's pack-transfer budget.

## Typed connection flow

`bedrock-client` exposes consumed owners for completed local transitions:

| Flow | Handoffs |
| --- | --- |
| Client Login | `ClientHandshake` → `ClientSettings` → `ClientLoginReady` → `ClientLogin` |
| Client packs | `ClientPackOffer` → `ClientPacks` → `PackComplete` |
| Client startup | `SpawnNegotiation` → `SpawnReady` → initialization acknowledgment |
| Accepting Login | `ServerHandshake` → settings/verification/authorization/exchange owners → `AcceptedLogin<Grant>` |

The original proof key, negotiated data and pending effects move with these
owners. A settings owner cannot create Login; transfer has no preload method;
startup has no initialization method until actual prerequisites produce
`SpawnReady`. Remote refusal, malformed input, expiry and I/O failure remain
runtime errors.

The application dispatches returned packets in order, installs compression and
ciphers on its retained connection, and preserves unrelated packets in a bounded
FIFO. A pure continuation cannot prove that a real socket flushed or that a
world authorized a player. Accepting Login requires a provider `LoginVerifier`
and an explicit application authorization callback. Its current handoff ends
before server pack advertisement/delivery and world attachment.

See the [integration guide](docs/integration.md) for packet routing, cipher
ordering, pack/startup handoffs and owner-preserving error/close handling. The
[client contract](crates/bedrock-client/README.md) describes each capability.

## Features and runtimes

| Root feature | Provides |
| --- | --- |
| Default | Synchronous batch codec and directional batch ciphers. |
| `login` | Offline/acquired-credential request formatting, server exchange and accepting verification primitives. |
| `raknet` | `RakNetConnection`, a caller-polled Tokio socket driver over the Cinnabar RakNet fork. |
| `messaging` | `PreparedMessaging`/`MessagingConnection`, composing a supplied SDK service socket with NetherNet. |

The optional edges start no runtime or background task of their own. RakNet owns
one socket and must be driven through `recv`, `flush` and capacity waits.
Messaging must keep `recv` or `maintain` polled; its underlying NetherNet Tokio
adapter owns the connected UDP task. A Bevy or custom-runtime application can
use the pure codec/client/pack owners with its own transport and scheduler.

Local transport close consumes send capability and retains a closing owner.
Borrowed drain/close waits keep accepted input and pending work across
cancellation. Completion describes local retirement; it does not acknowledge
remote delivery. Shared established Messaging senders observe global closure at
the runtime admission gate.

The crates currently use Git/path dependencies rather than crates.io releases.
Select one reviewed revision of this repository for its library crates and use
the matching generated packet/dependency graph from [Cargo.toml](Cargo.toml).
The manifest declares the required Rust version. Optional edges bring their
runtime dependencies only when enabled.

## Examples and checks

The [probe source](examples/client/src/main.rs) shows settings, compression,
Login, cipher installation and preserving a pack offer. It stops at the offer;
it does not download packs or enter a world.

```sh
cargo run -p bedrock-probe -- raknet 127.0.0.1:19132
cargo run -p bedrock-probe -- nethernet 127.0.0.1:19132 --offline-login
cargo run -p bedrock-probe -- nethernet-lan 127.0.0.1:19132 --offline-login
cargo test --locked
cargo test --locked -p bedrock-net --all-features
cargo fmt --all --check
```

The LAN probe targets the supplied IPv4 discovery endpoint. The HTTP path uses
HTTP signaling. Both use synthetic offline identity; account credentials and
account-specific admission remain application work. Optional RakNet Go
interoperability checks use the loopback-only helper in
[`tools/raknet-peer`](tools/raknet-peer) via `BEDROCK_NET_RAKNET_PEER`.

## Compatibility and license

Packet negotiation is tied to the generated protocol revision in the workspace
manifest. Deterministic regressions and synthetic peers do not establish full
vanilla, real-account, WAN, device or server compatibility. Accepting offline,
guest and legacy-chain Login, server pack delivery and a running-world bridge
are not supplied by the current accepting API. The library's startup observer
also leaves world loading, presentation and ongoing play to its caller.

The root crate offers MIT or Apache-2.0. Extracted `bedrock-client` and
`bedrock-packs` code retains its separately identified
[PolyForm Noncommercial license](LICENSE-CINNABAR). See [NOTICE](NOTICE) for
implementation references and the retained dependency/adaptation notices.
