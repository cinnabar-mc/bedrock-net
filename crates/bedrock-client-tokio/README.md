# bedrock-client-tokio

Caller-owned Tokio connection and transport adapters over the actual generated
packet codec. This crate creates no runtime, connection task or background worker.
The separate `bedrock-client` crate retains its runtime-free protocol typestates.

The default API provides `PacketIo` for an application's existing pump. Select
`raknet` or `nethernet` to use `connection::Connection` and the concrete
`transport::Transport` owners. Their constructors consume actual established
`RakNet`, protected messaging or Ready `NetherNet` associations. Dialing, endpoint
trust, account acquisition and membership stay with the caller. The standalone
`bedrock-probe` and Cinnabar use these same owners directly.

`connect::raknet::connect_resolved` races caller-resolved candidates using the
supplied `RakNet` options. `connect::lan` owns directed discovery and the same
Ready association under an explicit `DirectedLanConfig`; the caller supplies its
actual identity/trust, wire-admission selection and nonce bound. Local-world
eligibility remains caller policy. `connect::http::connect` consumes prepared
HTTP signaling and returns the actual Ready client for caller-owned first-use
key approval. These helpers retain the first absolute cutoff and credential
expiry, drop losing attempts, and create no replacement session owner. DNS,
address-mode choices, TLS/egress clients and service grants stay above them.
Canceling a borrowed wait does not establish that its owner retired; retain the
existing caller cleanup discipline.

Construct `Connection` with the actual `BatchLimits`, generated receive
`wire::Limits` and aggregate deferred-byte bound for your role. Its incoming-only
decoded ceiling activates at the original compression-settings transition;
outgoing/Login limits remain separate. Raw reads and replay retain original
header bits and payloads. Deferred entries use generated `wire::RawFrame` values,
and a malformed later header remains behind an already accepted read prefix.
`next_packet` decodes generated packets under the supplied field limits; UI and
other application validation remain above this owner.

`handshake::settings` consumes the original client settings continuation and
installs compression before the caller constructs metadata. `handshake::login`
accepts the caller's opaque, verified proof-bound token and original absolute
credential deadline, or explicit offline identity and caller UTC. Its result
retains the actual advertised pack offer, or the actual packless `StartGame` in
the same deferred FIFO. Late key exchange installs the verified streams before
its acknowledgment. UI errors, redirects and account/provider decisions remain
with the caller through typed `NegotiationError` values.

`packs::acquire` drives the original consuming pack states and flushes every
response immediately. Its borrowed `PackIo` performs only caller-owned preload,
completed-archive storage and store flush; the library opens no cache or HTTP
client. Early stack input remains in the same byte-bounded raw FIFO until the
original transfer is ready, with store references released before exclusive
archive handoff. A synchronous borrowed observer can record original reads and
successful effect vectors, but cannot replace packets or admit state.

With `nethernet`, `server::AcceptingConnection` consumes an actual accepted
association and creates an SDP-key-bound `bedrock_client::server::ServerHandshake`.
The caller configures signaling trust and supplies the matching proof key, deferred
byte bound and absolute deadline:

```rust,no_run
# #[cfg(feature = "nethernet")]
# async fn accepted_wire(
# accepted: nethernet_tokio::AcceptedSession,
# key: std::sync::Arc<p384::ecdsa::SigningKey>,
# options: bedrock_client::server::ServerHandshakeOptions,
# max_deferred_bytes: usize,
# deadline: std::time::Instant,
# ) -> std::io::Result<()> {
use bedrock_client_tokio::server::AcceptingConnection;

let (mut wire, handshake) = AcceptingConnection::from_nether(
    accepted, key, options, max_deferred_bytes, deadline,
).await?;
// Drive `handshake` with `wire.receive(deadline)` and the caller's Login policy.
# let _ = (&mut wire, handshake);
# Ok(())
# }
```

`prepare_packets` accepts generated primary-player effects. Keep each pending core
continuation until its matching prepared send completes, install compression or
ciphers only after that plaintext response flushes, and recheck current application
authority immediately before each capacity permit's synchronous commit. The mutable
connection borrow exposes wire mechanics, not Login or membership authority.
`begin_close` consumes the send-capable wrapper and returns a receive/finish-only
`RetiredAcceptingConnection`; settle retained output first. Both types preserve the
same connection and FIFO. The `test-support` feature exposes one real signed
association fixture for downstream integration tests.

Keep the same connection through settings, encryption and play. A canceled
receive, maintenance or close wait retains its original FIFO and lifecycle
owner. `prepare_body` retains one encoded accepted-`NetherNet` send; canceling a
borrow does not restart it. After `PreparedSend::next` grants capacity, check
current application authority and synchronously `commit` with no intervening
await. Cipher progress occurs once at that commit. Retirement seals new commits
and settles only the original receipt under the first cleanup cutoff, preserving
accepted input for ordinary reads. Local send completion does not prove remote
processing.

`PacketIo::close` retires sending while retaining accepted input. A caller that
has finished consuming game data can use `PacketIo::finish_close` on `Connection`
under its existing deadline. This delegates to `Transport::finish_close`, consuming
remaining reliable/unreliable transport input without clearing already decoded
`Connection` packets or creating a replacement Ready owner. Canceling this wait
retains the same closing transport. Other `PacketIo` implementations inherit a
final hook that delegates to their existing `close` unless they override it.
Dropping the connection drops the same underlying transport owners. Read-only
RTT observations withdraw when their original transport retires.

`WireIdentity` and the retained challenge are wire metadata, never authentication
or membership capabilities. The extracted implementation retains its
[`PolyForm` Noncommercial license](../../LICENSE-CINNABAR).
