# bedrock-net

Native Rust networking foundations for Minecraft Bedrock, developed for
[Cinnabar](https://github.com/cinnabar-mc/cinnabar) and reusable by other clients.

The workspace separates byte-oriented transport/batch processing in `bedrock-net`,
generated-packet client and accepting negotiation in [bedrock-client](crates/bedrock-client),
and reusable pack text/archive ownership in [bedrock-packs](crates/bedrock-packs).
The client crate owns generated-packet Login, verified key-exchange transitions,
bounded resource-pack negotiation, in-band integrity, final stack ordering and
spawn prerequisites. Applications retain account verification, I/O, deadlines,
loading/presentation policy and ongoing play. The core and client/pack crates
create no runtime; optional I/O adapters are separate edges.

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
let DecodeOutcome::Packets { packets: received, .. } = codec.decode(batches[0].clone())? else {
    unreachable!("compression is not enabled");
};
assert_eq!(received, [packet]);
# Ok::<(), bedrock_net::BatchError>(())
```

After NetworkSettings, consume the plain codec with `codec.negotiate(settings)`
before processing subsequent batches. This returns `BatchCodec<Negotiated>`;
there is no second negotiation/reset method on that owner. Outgoing batches use the selected algorithm and threshold; incoming
batches use their declared algorithm. Unknown or invalid compressed payloads
produce `DecodeOutcome::Dropped`. The caller must count/log these outcomes and
continue reading. Framing, missing compression headers and size-limit violations
return errors. A malformed batch never exposes a partial packet list.
Empty server entries are skipped without consuming packet capacity. Successful
decode outcomes include `skipped_empty_packets` for caller diagnostics; wire and
decoded byte ceilings still apply. Empty outgoing packets remain errors.

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
Enable `login` for offline or authenticated request encoding and server key
exchange. The caller owns its P-384 signing key, UTC time, identity claims and
validated client-data JSON. The helpers retain raw client data, sign
line-terminated JSON and produce the opaque connection request used by
protocolgen. Server tokens are bounded,
verified with their DER key and used to derive the full-width ECDH session key.
`finish_key_exchange` returns independent outgoing/incoming ciphers. Its
self-contained signature establishes key possession; endpoint trust remains
with the transport/application. `encode_authenticated_request` formats an already
acquired multiplayer credential without changing it. Acquire that credential for
the same connection key through an account service such as
[bedrock-services](https://github.com/cinnabar-mc/bedrock-services); account I/O
stays outside this library.

The accepting Login helper requires a caller-owned `LoginVerifier` using trusted
provider policy. It verifies client metadata with that provider's bound proof key;
it never authenticates an XUID from raw JWT claims or an untrusted header key.
The verifier can retain signed name, canonical UUID and PlayFab identifiers with
`TrustedIdentity::with_player_identity`; `AuthenticatedLogin::player_identity`
borrows them and revalidation rejects changes. Missing presentation stays absent.
Recognized outer Login and nonce fields accept Go's field casing; ambiguous
aliases are rejected without rewriting signed metadata. Peer JSON diagnostics
retain no input values. JWT claim and JWS header names keep their original policy.
`bedrock_client::server` exposes consumed settings, verified Login, explicit
caller authorization, cipher acknowledgment and pack-preparation capabilities.
Completed owners have private constructors and retain the original deadline/key;
caller grants remain explicit application authority. Pending I/O continuations
retain exact packets/streams for the real adapter's flush/install contract.
Accepting pack delivery continues through owned read/write continuations and
actual caller-supplied world definitions; it supports original memory or external
archive sources without loading disk packs wholly into RAM.
Legacy/offline/guest accepting Login, an accepting listener and running-world
bridging remain unimplemented. See the [packet lifecycle contract](crates/bedrock-client/README.md).

Enable the `raknet` feature for `raknet::RakNetConnection`, a Tokio driver over a
pinned [bedrock-crustaceans/raknet](https://github.com/bedrock-crustaceans/raknet)
protocol engine, with queued ordering-window and offline negotiation fixes in the
Cinnabar fork. Sustained
application traffic follows congestion control and sends ready datagrams without
a fixed flush delay. One connection owns its socket and protocol state and spawns no
background tasks. Queue complete messages with `queue_send`, then keep `recv`
polled in the session network loop to service acknowledgements and timers. `flush`
sends immediately available datagrams. Cancelling these waits retains pending
state; dropping a connection attempt or connection releases its socket. Transport messages
retain their batch marker. Each attempt generates a fresh client identity from OS entropy
before sending any datagrams; entropy failure returns an I/O error and releases the socket.
The identity remains stable throughout retries and protected handshakes. Transport
timers and wire uptime use a monotonic clock, independently of authentication UTC.
Receive queue capacities and handshake/close deadlines are explicit options. `max_mtu` caps probes
and connected datagrams for local tunnels or VPNs; invalid caps fail before socket
creation. Probe size failures
advance discovery, and Request 1 discovery continues independently while Request 2
retries. Initial MTU negotiation tolerates up to ten recognized transient UDP
read errors across both offline phases; other errors remain fatal and the overall
handshake deadline still applies. Application packets received during reliable
setup stay in a FIFO bounded by the same receive options and transfer into the
established session. A coalesced peer close follows its completed packet prefix.
These deterministic transitions still need validation on real network paths and
devices. `wait_send_capacity` services ACKs when the outgoing byte
budget is full, retaining inbound messages for the next `recv`. Complete earlier
messages drain before terminal errors. Local close consumes the established owner
with `begin_close(self)`. Its `ClosingRakNetConnection` has no send capability;
borrowed `finish_close`/`recv` waits keep the same original close deadline, pending
datagram and accepted FIFO when cancelled. A failed transition returns that closing
owner through `RakNetCloseError::into_parts`. `try_finish` yields a capability-free
`ClosedRakNetConnection` only after socket release and FIFO/terminal observation.
This is local retirement, not a remote delivery acknowledgment.

Cargo.toml declares the minimum Rust version required by the pinned transport dependency.
The driver selects the socket family after normalizing mapped IPv4 endpoints and
advertises its connected socket's local address during setup. Native IPv6 scope
IDs remain available for socket routing and are omitted from protocol addresses.

For Go transport interoperability checks, build the loopback-only helper under
`tools/raknet-peer` and set `BEDROCK_NET_RAKNET_PEER` to that executable before
running `cargo test --locked -p bedrock-net --features raknet`.

Enable `messaging` for the optional Player Messaging runtime edge. The application
acquires a protected SDK `MessagingSocket` from its selected account, then moves
it into `messaging::PreparedMessaging` with the exact advertised local network ID
and the intended peer's messaging UUID. Supply the connection's shared proof-key
SDP identity, configured peer trust and original absolute deadline to `connect`.
The edge hands the SDK's original TURN expiry to NetherNet's bounded UDP resolver
and ICE owner. It performs one connection attempt and creates no runtime or task.

Keep polling `MessagingConnection::recv` during connection use, including while
waiting for writes through its established `sender()` capability. When application input
is full, poll `maintain` instead: it drives service/control/signaling without
consuming game data. Both paths drive heartbeats, receipts and late ICE candidates.
Maintenance stages a service terminal for the existing receive FIFO to drain
before one error/EOF; it creates no additional payload backlog or task. SDK request IDs correlate existing caller
requests; offers require service acceptance and the intended peer's receipt.
Incoming signals are routed by authenticated envelope UUID and connection ID,
and acknowledged after bounded transport admission. Cancellation drops unsent
waits without automatically retrying an ambiguous write. Closing or dropping the
owner retires its service socket and signaling waits. `begin_close(self)` consumes
local sender capability into `ClosingMessagingConnection`, which can drain only the
original accepted reliable prefix and one terminal. `try_finish` succeeds after
that terminal; it does not claim a remote acknowledgment or actor join. Existing
shared senders observe closure through the original runtime admission gate.

One bounded service batch can wait for the smaller transport queue while socket
control, heartbeats and completions continue. Envelopes retain their original
deadline and a single receipt ID. Local SDK capacity waits retain an unadmitted
send or receipt; admitted transport signals are never delivered twice. Incoming
expiry is checked at transport queue publication, and final connection handoff
refuses and retires a ready connection at or after its original setup deadline. A service
failure closes the transport and drains its existing accepted reliable FIFO
before reporting one error. No additional application-data backlog is created.

Account persistence, world/session admission, join nonces and retry policy remain
application-owned. This edge does not acquire an MPSD session or host a world.
The new adapter tests exercise the real pure SDK/caller boundaries with synthetic
messages; real-account, protected-socket and WAN acceptance remain unverified.

This is an incremental implementation. Production NetherNet integration, the
full Login/session lifecycle, services and broader server validation are still
pending. The existing Cinnabar Go backend remains the production implementation.

The standalone `bedrock-probe` workspace binary composes generated protocolgen
packets with the native batch codec. Run
`cargo run -p bedrock-probe -- <raknet|nethernet|nethernet-lan> IP:PORT` to request
network settings and close. Add `--offline-login` to send a synthetic self-signed
Login and stop after acceptance and the resource-pack offer. The probe retains
packets across phase changes and handles optional application encryption; it
does not negotiate or download packs. RakNet uses Minecraft batch ciphers after
key exchange. NetherNet verifies the server handshake and uses its DTLS
transport without adding Minecraft batch ciphers.

The `nethernet` path uses HTTP signaling and a self-signed client identity.
`nethernet-lan` directs discovery to an explicit IPv4 loopback fixture, requires
advertised self-signed admission and a nonce, and copies that nonce into Login
metadata. It does not scan the LAN. The transport adapter is being evaluated for
later library integration; account authentication and the full startup/session
API are pending. The LAN probe has completed settings, offline Login and a
compressed pack offer against an isolated BDS 1.26.52.3 using synthetic Android
metadata and an original skin. Other metadata/platforms and broader server
compatibility remain unverified. The helper tests independently verify request
signatures and key agreement with the pinned Go implementation.

The three library crates are the default workspace members. The standalone probe
remains an explicit member; its runtime and transport evaluation dependencies
stay outside the libraries' normal dependency graphs. The generated codec pin
is shared by the probe and client crate in the workspace manifest.

Run `cargo test --locked` for focused codec tests and `cargo fmt --all --check`
for formatting. See [NOTICE](NOTICE) for implementation references and licensing.
The root library retains its MIT/Apache license choice. Extracted Cinnabar code
in the client and pack crates retains its separately identified PolyForm license.
