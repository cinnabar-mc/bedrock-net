# Integrating the libraries

Use the lowest layer that owns the data you need. `bedrock-net` processes encoded
packet bytes. `bedrock-client` processes protocolgen's generated packets and
returns protocol effects. `bedrock-packs` owns archive/text data. None of those
pure owners selects an account, opens a world or schedules I/O for you.

The application retains one connection's transport, batch codec, cipher streams,
proof key, unread packet FIFO and absolute setup deadline. Multiple sessions can
be scheduled by the caller; the pure owners impose no executor or task model.

## Drive a connection

1. Create the transport and original proof key, then start the protocol owner.
   Keep one codec, cipher pair and bounded unread-packet FIFO for that connection.
2. Decode each transport batch once. Feed its entries to the active owner in
   order, retaining returned continuations and unrelated packets. Drain unread
   entries before receiving another batch.
3. Dispatch returned effects in order. A pending settings, exchange or chunk
   owner keeps its next transition until the adapter completes the documented
   send/flush/install work. Recheck application authority after capacity waits
   and immediately before actual admission.
4. Use the caller's original deadlines. On a failed protocol transition, recover
   the owner when the error exposes `into_parts` and retire the same connection.
   Recovering ownership does not restart a sealed phase or its cipher stream.

The [probe](../examples/client/src/main.rs) demonstrates the client loop. Its
[session owner](../examples/client/src/session.rs) shows the codec/FIFO boundary;
its [transport owner](../examples/client/src/transport.rs) shows concrete I/O.
These are example application owners, not additional public library APIs.

## Framing and compression

A transport message contains one batch. `BatchHeader::RakNet` includes its leading
marker; `BatchHeader::NetherNet` has no marker. Encoded packet slices include their
generated packet headers and omit the batch entry's length prefix.

Start with `BatchCodec<Plain>`. Decode each received batch once, retain its packet
entries in order and decode bodies with the matching protocolgen crate. Feed only
the relevant generated packet to the active negotiation owner. A phase change
must preserve unread siblings from the same batch ahead of later network input.

Actual NetworkSettings yields `CompressionSettings`. Install it by consuming the
retained plain codec into `BatchCodec<Negotiated>` before Login. There is no reset
or second negotiation method. Outgoing compression uses the selected algorithm
and threshold; incoming compression follows each batch's declaration.

| Decode result | Caller action |
| --- | --- |
| `Packets` | Process entries in order and count `skipped_empty_packets`. |
| `Dropped` | Count/log the compression failure and continue with the next batch. |
| `BatchError` | Handle the framing/limit failure; no partial packet list was delivered. |

Apply the encoded-byte ceiling before decryption and the decoded-byte/packet
ceilings during batch decode. Application deferred input needs its own explicit
byte and packet limits. Protocol packet decoding, unknown IDs, unused fields and
terminal packet policy belong to the caller, not the batch codec.

## Cipher ownership

`BatchEncryptor` and `BatchDecryptor` own independent continuous AES-256-CTR state
and checksum counters. For RakNet, remove the batch marker before encryption and
restore it around the resulting ciphertext. On receive, verify/decrypt the body
before decompression. NetherNet already secures transport with DTLS; configure
`HandshakeOptions::batch_encryption` for that transport rather than adding a
second application cipher automatically.

A verified `ClientKeyExchange<C>` owns the exact continuation, optional streams
and acknowledgment. `into_parts` transfers them together. Install both streams,
send the original acknowledgment, then resume its continuation. The accepting
exchange requires sending/flushing its token in plaintext before handing out
streams.
The [probe session](../examples/client/src/session.rs) shows the byte boundary and
[probe handshake](../examples/client/src/main.rs) shows the generated effects.

Never restart a cipher or discard ciphertext after advancing its stream. Retain
an admitted outgoing batch until the transport confirms local emission; retrying
its original plaintext would advance the stream again. Integrity failure
invalidates the affected direction. A compression drop still consumes that
received encrypted batch's stream position.

## Client Login

Give `ClientHandshake::new` the caller's P-384 key or an `Arc<SigningKey>` shared
with account/transport admission. It retains that allocation throughout Login
and server exchange. Entropy/key generation remains with the caller.

1. Consume `start` and send the returned uncompressed RequestNetworkSettings.
2. Feed generated packets to `ClientSettings::receive`. `Pending` returns its
   owner and unrelated input; `Ready` returns actual compression and
   `ClientLoginReady`.
3. Install compression, format one offline or authenticated Login, and dispatch
   that exact packet. An authenticated formatter preserves the acquired token;
   it does not acquire or verify account/issuer/proof/expiry authority.
4. Drive `ClientLogin::receive`, send returned effects in order and apply any
   verified exchange. `Packs` hands off the admitted offer plus the same late
   Login/key-exchange owner.

The examples below use the workspace's `bedrock_protocol` alias for the generated
packet crate. Match that dependency and revision when using these types in an
application; its declaration is in [Cargo.toml](../Cargo.toml).

Formatting can fail before dispatch while leaving the original readiness owned:

```rust
use bedrock_client::handshake::{ClientLogin, ClientLoginReady, HandshakeError};
use bedrock_protocol::packets;
use serde_json::value::RawValue;

fn prepare_login(
    ready: ClientLoginReady,
    token: &str,
    metadata: &RawValue,
) -> Result<(ClientLogin, packets::Login), (ClientLoginReady, HandshakeError)> {
    ready.login_authenticated(token, metadata)
        .map_err(|error| error.into_parts())
}
```

That error does not mean Login was sent. By contrast, received-packet errors end
the active handshake. Close the real connection rather than constructing a
replacement phase around the same stream. Recheck acquired credentials and
original absolute deadlines immediately before actual transport admission,
including after a capacity wait.

`LoginEvent::Unhandled` and other returned unrelated packets remain caller-owned.
Handle Disconnect, Transfer and refusal statuses promptly. Keep unrelated startup
input in the bounded FIFO; do not silently discard it during negotiation.

## Client packs and startup

`ClientPackOffer` exposes original offer metadata and accepts caller-validated
cache/CDN preloads. Send the returned cache status once when present. Consume
`start` only after preload policy is settled; `ClientPacks` then owns transfer and
late Login controls together. It has no preload method.

The transfer bounds retained archive bytes and request work, validates in-band
integrity and processes the server's final stack in its declared order, including
subpacks, required status and recognized built-ins. Cache/CDN reads, persistence,
archive validation/application and presentation remain external.

Only actual final-stack processing returns `PackComplete`. Its `start_spawn`
transfers the original stack acknowledgment and archive handoff alongside a
`SpawnNegotiation` configured with the caller's radius request. Send the
acknowledgment before processing startup traffic. `into_parts` supports stopping
at the pack boundary. A constructed `ResourcePackHandoff` is data; it cannot
construct another completion capability.

Each `SpawnUpdate` may contain several effects. Dispatch `request_radius`, start
application preparation from `startup`, preserve/handle `deferred`, and retain
`ready` without losing siblings. Definitions become available before all network
prerequisites complete so loading can progress concurrently. Only actual startup
input produces `SpawnReady`; after presentation is ready, consume
`finish_loading` once and send its initialization acknowledgment.

The standalone `PackOffer` → `PackNegotiation` flow uses the same transfer engine
without client Login controls. `SpawnNegotiation::new` also supports external
prepared handoffs, but only constructs an observer: it does not prove Login,
pack completion, account authority or world readiness.

## Accepting Login

The Login-only handoff yields `AcceptedLogin<Grant>`. Optional `start_packs`
continues through owned chunk read/write and caller-selected startup data. Supply
the listener and current application authorization yourself. See the
[accepting capability contract](../crates/bedrock-client/README.md) and
[server API](../crates/bedrock-client/src/server/lifecycle.rs).

Supply the original server key, absolute monotonic deadline, configuration and
any already verified transport peer key. A caller-owned `LoginVerifier` supplies
trusted provider policy; there is no permissive/default verifier. The accepting
helper verifies client metadata against that provider's bound proof key rather
than an untrusted JWT header. Modern authenticated Login is supported; offline,
guest and legacy chains are outside this accepting API.

`ServerHandshake` first produces `PendingServerSettings`. Borrow its packet,
send/flush it uncompressed, install its compression on the retained codec, then
consume `flushed` into `ServerLogin`. Actual verification produces `VerifiedLogin`.
Its consuming `authorize` callback must consult the application's real current
account/world/session authority and return the concrete grant to retain.
Invites, public service cards, SDP and client-supplied metadata alone do not
supply that authority.

`ApprovedLogin::accept` revalidates the original identity and either produces a
pending exchange or the already-encrypted-transport continuation. With application
encryption, supply fresh caller-generated sixteen-byte salt, send/flush the exact
server token in plaintext, then consume `PendingServerKeyExchange::flushed` and
install its returned streams before reading the encrypted acknowledgment.
`ServerPacksReady::finish` revalidates and consumes Login/grant into `AcceptedLogin`.
No LoginSuccess or pack offer is emitted by these steps.

The original deadline never restarts. Recheck application grants after waits
before later dispatch/attachment. `ServerTransitionError::into_parts` preserves
its owner and redacted cause for retirement; it does not reset a failed exchange.
Pending continuations express the real adapter's explicit flush/install contract.
A pure owner cannot independently certify a socket operation.

## Accepting packs and startup

Consume `ServerPacksReady::start_packs` with the selected `ServerPackSnapshot`,
delivery bounds and original verifier/time. It validates the snapshot before
returning LoginSuccess and the offer. Send those effects in order, then feed
generated packets to `ServerPacks::receive`:

| `ServerPackEvent` | Adapter action |
| --- | --- |
| `Send { session, packets }` | Dispatch all packets, then retain that session for the next input. |
| `ReadChunk(read)` | Read exactly its `archive_index`, `offset` and `byte_len` from the retained source lease. Successful `supply` returns a `PendingServerChunk` directly; handle it as in the `Chunk` row. |
| `Chunk(chunk)` | Send its borrowed `packet`, then consume `flushed` after actual I/O. Dispatch all returned follow-up packets before feeding more input to the returned session. |
| `WorldReady(ready)` | Supply the selected world's definitions through `start_world`. |
| `Unhandled { session, packet }` | Handle terminal input promptly; preserve other input and the returned session. |

Both memory and external archives follow the same sequential chunk contract.
The flush follow-up can advertise the next archive's `ResourcePackDataInfo`.
An external snapshot records the original size/hash; the adapter retains the
immutable source and performs its reads. A pending read or chunk owns the whole
session, so keep pipelined input in the existing bounded FIFO until it completes.
Recheck the retained grant at actual dispatch after I/O waits.

`ServerWorld` contains the selected world's generated definitions and radius
policy. `ServerWorldReady::start_world` returns startup effects and
`ServerSpawning`; send the effects before processing further peer input. Radius
negotiation and the actual runtime-ID acknowledgment produce `ServerInitialized`.
Its `finish` revalidates the provider and returns `AcceptedSession`, carrying the
original Login, caller grant and observed cache/radius. Recheck application
authority before attaching that player to the running world.

Snapshot validation before advertisement can return the original Login owner
for a corrected local snapshot. Errors during protocol progress return sealed
continuations through `ServerSessionTransitionError::into_parts`; keep their
original output for retirement. There is no default verifier or default world.

## Optional RakNet edge

With `raknet`, `RakNetConnection::connect(peer, options)` returns only after real
transport negotiation. One connection owns its Tokio UDP socket and protocol
state without spawning a background task. Keep `recv` polled to advance ACKs,
retransmission and pings. `queue_send` admits one complete message; `flush` emits
currently ready datagrams. A full send budget uses `wait_send_capacity`, which
also retains inbound messages for later `recv`.

Use `RakNetOptions` for receive/send budgets, setup/close deadlines and the local
MTU cap. The driver normalizes mapped IPv4 before choosing the socket family,
uses the connected socket's local address and keeps scoped IPv6 routing local to
the socket. Per-attempt GUIDs come from OS entropy and remain stable for retries;
transport time uses a monotonic clock, independently of authentication UTC.

Consume local send permission first, then borrow the retained closing owner for
cancelable work. Even a failed transition returns that owner:

```rust
use bedrock_net::raknet::{ClosingRakNetConnection, RakNetConnection, RakNetError};

fn begin_retirement(
    connection: RakNetConnection,
) -> Result<ClosingRakNetConnection, (ClosingRakNetConnection, RakNetError)> {
    connection.begin_close().map_err(|error| error.into_parts())
}

async fn finish_retirement(closing: &mut ClosingRakNetConnection) -> Result<(), RakNetError> {
    closing.finish_close().await
}
```

`ClosingRakNetConnection` exposes no application send. `recv` drains its accepted
prefix before the original terminal; canceled borrowed waits retain pending
input/datagrams and the original close deadline. `try_finish` returns
`ClosedRakNetConnection` only after socket release and FIFO/terminal observation.
Dropping the owner releases its socket. Local completion is not peer delivery.

## Optional Player Messaging edge

With `messaging`, move the selected account's protected SDK `MessagingSocket`
into `PreparedMessaging`, together with the advertised local NetherNet ID and
intended peer's messaging UUID. `connect` needs the same proof-key SDP identity,
explicit peer trust and original deadline. It uses the acquired TURN expiry
unchanged and makes one attempt. Account/session admission and ambiguous retry
policy remain external.

This edge creates no runtime or task of its own; the NetherNet Tokio transport
uses its connected-session task. Keep `MessagingConnection::recv` polled while
using its established `sender()` capability. When application receive capacity
is unavailable, poll `maintain`: it advances service control, heartbeats, receipts
and late ICE without consuming game data or making another payload queue.

Authenticated envelope UUID and connection ID select incoming signals. A service
receipt is sent after bounded transport admission. Unadmitted waits retain their
original deadline; cancellation does not automatically retry an ambiguous write.
A service failure retires the transport and stages one terminal after its accepted
reliable prefix.

`begin_close` synchronously returns `ClosingMessagingConnection`, retaining that
prefix and terminal while removing local sender/maintenance capability.
`try_finish` succeeds only after terminal observation. Existing cloned established
senders observe shared closure at runtime. No new SDK socket, account proof or
application backlog is created by closing.

For accepting transports, move the upgraded socket and its exact original local
network ID into `messaging::server::PreparedMessagingServer`. Its consuming `bind`
takes the existing `ConnectionConfig`, `CallerServerSignalingConfig` and original
setup deadline. Supply an answer signer and explicit offer trust. The returned
`MessagingServer` owns the actual bounded NetherNet listener and the same service
queue/receipt engine used by the connecting edge. Poll `accept` to receive an
established `nethernet_tokio::AcceptedSession`; poll `maintain` beside peer I/O
when not accepting another session. Transport establishment supplies no Minecraft
Login, directory membership or world authorization.

The accepting edge uses caller-supplied `ServerIceConfig`; it does not acquire or
renew TURN credentials. Each new offer checks their original absolute expiry.
`set_server_ice` changes the configuration for later offers without changing an
existing peer's allocation. The application owns any renewal and explicit updates
of those live sessions. Configure signed assertions and Login admission according
to the application's actual service/provider policy. The default requires an SDP
identity. Explicit `ConnectionConfig::allow_anonymous_offers` accepts an absent
assertion while retaining the selected trust and fingerprint checks for every
present assertion. This option never authorizes a Minecraft Login.

Consuming `MessagingServer::begin_close` synchronously retires the service routes.
Its `ClosingMessagingServer` retains the original listener join; call `finish_close`
and then consume `try_finish`. Previously returned sessions retain their original
receive queues with their callers. Dropping a borrowed close wait preserves the
listener join, while dropping the whole owner explicitly abandons that wait.

## Runtime choice

A custom executor or Bevy application can feed generated packets and caller time
to the pure owners, dispatch their effects from its own transport, and retain
readiness until presentation completes. Enabling the optional edges is a separate
choice for applications already using Tokio. Neither design requires one task
per pure protocol owner.

The [probe](../examples/client) supplies a Tokio runtime and concrete transport
integration for settings and optional offline Login. Its Login path stops at a
pack offer. Applications that need authenticated Login, complete pack transfer or
accepting world startup compose those owners on their existing runtime and supply
the corresponding account, source and world policy.
