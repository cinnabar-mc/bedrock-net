# bedrock-net

Native Rust libraries for Minecraft Bedrock batch framing, Login, resource-pack
delivery and startup negotiation. Use the protocol owners with your own
transport and scheduler, or enable the optional Tokio transport edges.

Applications supply account and endpoint policy, credentials, pack sources,
world definitions and ongoing play. The libraries retain protocol state and
return the next owned continuation and its effects.

## Choose a layer

| Crate | Responsibility |
| --- | --- |
| [`bedrock-net`](src/lib.rs) | Encoded packet batches, compression and directional ciphers; optional Login primitives and transport edges. |
| [`bedrock-client`](crates/bedrock-client) | Sans-I/O client and accepting negotiation over generated packets, including pack transfer and startup. |
| [`bedrock-client-tokio`](crates/bedrock-client-tokio) | Optional caller-owned connection, codec/FIFO/cipher and established transport lifecycles; no runtime or session task is created. |
| [`bedrock-packs`](crates/bedrock-packs) | Runtime-independent pack text, owned archive handoffs and content-key lifetime. |

[protocolgen](https://github.com/cinnabar-mc/protocolgen) owns the version-specific
packet schemas and serializers. [bedrock-services](https://github.com/cinnabar-mc/bedrock-services)
owns account authentication and service traffic. This workspace consumes their
outputs; applications select accounts, authorize world/session joins, acquire
credentials and decide retry, cache, rendering and ongoing-play policy.

The three libraries are the default workspace members. Their pure owners perform
no socket, HTTP, filesystem or clock I/O and create no runtime. Callers supply
time to operations that need it. A Bevy or custom-executor application can drive
these owners directly; enabling an optional Tokio edge is a separate choice.

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
    DecodeOutcome::Packets { packets, .. } => assert!(packets.eq([packet])),
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
Batch framing and size violations return `BatchError`; all entry lengths are
validated before any packet is exposed. Packet headers and bodies still need
decoding. Empty incoming entries are skipped and counted. Limits are
explicit library policy, adjustable for an application's pack-transfer budget.
Decoded packets are an owning iterator over one validated body; consume it as
needed rather than collecting unread packets. `max_packets` controls outgoing
splitting. Incoming batches use the byte bounds by default; set
`max_incoming_packets` to enforce a separate nonempty packet-count ceiling.
After negotiating compression, `with_incoming_decoded_limit` can set a separate
incoming decoded-byte ceiling. It preserves the original outgoing, wire and
packet-count limits; the initial plaintext phase keeps its original byte policy.

## Typed connection flow

`bedrock-client` exposes consumed owners for completed local transitions:

| Flow | Handoffs |
| --- | --- |
| Client Login | `ClientHandshake` → `ClientSettings` → `ClientLoginReady` → `ClientLogin` |
| Client packs | `ClientPackOffer` → `ClientPacks` → `PackComplete` |
| Client startup | `SpawnNegotiation` → `SpawnReady` → initialization acknowledgment |
| Accepting Login | `ServerHandshake` → settings/verification/authorization/exchange owners → `ServerPacksReady<Grant>` or Login-only `AcceptedLogin<Grant>` |
| Accepting packs | `ServerPacks<Grant>` → owned chunk read/write continuations → `ServerWorldReady<Grant>` |
| Accepting startup | `ServerSpawning<Grant>` → `ServerInitialized<Grant>` → `AcceptedSession<Grant>` |
| Packless upstream relay | `ServerPacksReady<Grant>` → pending LoginSuccess flush → `ServerRelaying<Grant>` → actual forwarded initialization |

Methods consume the current phase and return its continuation. Install returned
compression or ciphers and dispatch effects before advancing that continuation.
`ClientSettings` exposes no Login formatter, pack transfer exposes no preload
method, and only `SpawnReady` exposes the initialization acknowledgment. The
original key and negotiated data move with the owner.

These types constrain local call order. Remote refusal, malformed input, expiry
and I/O failure still return errors. Preparation errors such as Login formatting
can return the unchanged owner for correction. Accepting transition errors retain
their continuation for retirement. Recovery does not reset a deadline or stream.

The application dispatches returned packets in order, installs compression and
ciphers on its retained connection, and preserves unrelated packets in a bounded
FIFO. A pure continuation cannot prove that a real socket flushed or that a
world authorized a player. Accepting Login requires a provider `LoginVerifier`
and an explicit application authorization callback. Pack delivery retains the
original memory archive or adapter-owned external source through sequential
read/write continuations. Startup requires the actual caller-selected world
packet definitions; completion does not attach that world to a player.

The verifier can retain signed name, canonical UUID and PlayFab identifiers with
`TrustedIdentity::with_player_identity`; `AuthenticatedLogin::player_identity`
borrows them and revalidation rejects changes. Missing presentation stays absent.

The accepting APIs provide protocol continuations through `AcceptedSession`.
The application supplies its listener, current authorization and running-world
attachment. It can also stop at the Login-only handoff.
An upstream without a pack phase uses `relay_without_packs`; it creates no pack
metadata or acknowledgment. The caller flushes its LoginSuccess before forwarding
the real startup. Runtime, registry, radius/spawn and Initialized checks remain.

See the [integration guide](docs/integration.md) for packet routing, cipher
ordering, pack/startup handoffs and owner-preserving error/close handling. The
[client contract](crates/bedrock-client/README.md) describes each capability.

## Features and runtimes

| Root feature | Provides |
| --- | --- |
| Default | Synchronous batch codec and directional batch ciphers. |
| `login` | Offline/acquired-credential request formatting, server exchange, accepting verification and pure ClientData validation. |
| `provider-verification` | Pure configured issuer/JWK verification for Login and signed SDP, using caller-supplied UTC; includes `login` and NetherNet identity primitives. |
| `raknet` | `RakNetConnection`, a caller-polled Tokio socket driver over the Cinnabar RakNet fork. |
| `messaging` | `PreparedMessaging`/`MessagingConnection` and `messaging::server`, composing a supplied SDK service socket with connecting or accepting NetherNet. |

The optional edges start no runtime or task of their own. RakNet owns one socket;
keep `recv` or `maintain` polled for protocol progress, use `queue_send` for admission and drive
`flush` for local emission. `wait_send_capacity` services that same connection
when its send budget is full. `maintain` retains accepted input and defers new
reliable input when aggregate capacity is full; drain the FIFO and its terminal
through `recv`. One original message head may wait outside the FIFO, while a
message exceeding the whole configured byte allowance still fails. Messaging
needs `recv` or `maintain` polled; its
underlying NetherNet Tokio adapter owns its bounded transport workers. Accepting
`MessagingServer` needs `accept` or `maintain` polled and takes caller-supplied
ICE configuration. It publishes no world or activity and does not authorize Login.

An accepting JSON-RPC server can request fresh TURN credentials with
`begin_turn_refresh(deadline)` and finish that exact request with
`finish_turn_refresh(&receipt)`. Keep the receipt across canceled waits; it belongs
to that server and cannot be reused on another one. Finish the request, explicitly
retire it with `cancel_turn_refresh(&receipt)`, or close the server before abandoning
it. Explicit cancellation releases only that receipt's local wait and result;
an admitted write can still reach the service, with late responses ignored.
The result moves the actual SDK credential
owner once and preserves its expiry. This operation does not refresh account
authentication, replace ICE configuration or renew an existing allocation.

The caller can install a qualified answer identity, offer trust and ICE
configuration with `set_identity`, `set_token_trust` and `set_server_ice`.
Coordinate these changes before accepting another offer. Pending and accepted
peers retain their original transport and signer owners; the setters perform no
service requests or atomic renewal transaction.

Choose the service dialect from the acquired route before connecting.
`PreparedMessaging::new` takes a Player Messaging UUID;
`PreparedMessaging::new_legacy` takes the original legacy string recipient and a
matching legacy SDK socket. `recipient()` preserves that typed distinction.
Legacy offer completion uses the service delivery outcome; it does not invent a
peer receipt. Supply signed identity and explicit answer trust in both cases.
Only the explicit legacy route may opt into missing answer assertions; any
present assertion still passes the configured verification.

Local transport close consumes send capability and retains a closing owner.
Borrowed drain/close waits keep accepted input and pending work across
cancellation. Completion describes local retirement; it does not acknowledge
remote delivery. Shared established Messaging senders observe global closure at
the runtime admission gate.
For an accepting Messaging server, `begin_close` seals its routes immediately and
retains the original service socket. Keep calling the resulting owner's
`finish_close` to drive its bounded WebSocket close and join the listener.
Canceling that wait preserves both owners and the original close cutoff.

The crates currently use Git/path dependencies rather than crates.io releases.
Select one reviewed revision of this repository for its library crates and use
the matching generated packet/dependency graph from [Cargo.toml](Cargo.toml).
The manifest declares the required Rust version. Optional edges bring their
runtime dependencies only when enabled.

## Examples and checks

The standalone `bedrock-probe` binary demonstrates settings and optional offline
Login. Its Login path stops at the pack offer. Read its existing owners together
when adapting it:

| Example source | Shows |
| --- | --- |
| [main.rs](examples/client/src/main.rs) | Consuming settings/Login phases and handling returned effects. |
| [session.rs](examples/client/src/session.rs) | One codec/cipher pair and preserving unread batch entries. |
| [transport.rs](examples/client/src/transport.rs) | Concrete transport setup, send and retirement. |

```sh
cargo run --locked -p bedrock-probe -- raknet 127.0.0.1:19132
cargo run --locked -p bedrock-probe -- nethernet 127.0.0.1:19132 --offline-login
cargo run --locked -p bedrock-probe -- nethernet-lan 127.0.0.1:19132 --offline-login
cargo test --locked
cargo test --locked -p bedrock-net --all-features
cargo fmt --all --check
```

Each probe invocation needs a peer listening at the supplied endpoint. The
default probe only requests settings; `--offline-login` uses synthetic identity.
The LAN mode targets an IPv4 discovery endpoint; the `nethernet` mode uses HTTP
signaling. Account authentication, pack download and entering a world remain
application work.

## Protocol scope and license

Packet negotiation uses the generated protocol revision in the workspace
manifest. The accepting APIs handle modern authenticated Login; offline, guest
and legacy-chain accepting Login are unsupported. World loading, presentation,
running-world attachment and ongoing play belong to the application.

The root crate offers MIT or Apache-2.0. Extracted `bedrock-client`,
`bedrock-client-tokio` and `bedrock-packs` code retains its separately identified
[PolyForm Noncommercial license](LICENSE-CINNABAR). See
[NOTICE](https://github.com/cinnabar-mc/bedrock-net/blob/dev/NOTICE) for
implementation references and the retained dependency/adaptation notices.
