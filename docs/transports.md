# Transports

Use NetherNet with HTTP signaling for direct servers, LAN discovery for nearby
worlds, or Player Messaging when you already have its service socket. Your application supplies the
runtime, endpoint policy and account credentials.

## Features

These are features of the root `bedrock-net` crate:

| Feature | Adds |
| --- | --- |
| Default | Synchronous batch framing and compression. |
| `login` | Login formatting, accepting verification, server-token validation and client-data validation. |
| `provider-verification` | Configured issuer/JWK verification for Login and signed SDP; includes `login`. |
| `messaging` | Client and server adapters combining an SDK service socket with NetherNet. |

The separate `bedrock-client-tokio` crate has a `nethernet` feature.
It enables its concrete connections and negotiation helpers. Neither crate
starts a runtime. The underlying NetherNet adapters use bounded transport workers.

## Connect with Tokio

`bedrock-client-tokio::connect` provides these entry points:

| Route | Function and inputs |
| --- | --- |
| Directed LAN | `lan::connect_resolved` or `lan::connect_directed`: discovery addresses and `DirectedLanConfig`. |
| HTTP signaling | `http::connect`: prepared HTTP signaling, endpoint, configuration and expiry. |

The LAN helpers select among the supplied addresses. They keep the
first deadline and credential cutoff and drop losing attempts. LAN configuration
includes identity, trust, advertisement selection and a nonce bound. HTTP setup
returns a Ready client so your application can approve a first-use key before
wrapping it in `Transport::from_http`. DNS, TLS clients, egress, local-world
eligibility and service authorization belong to the application.

For accepting connections, pass the established session to
`AcceptingConnection::from_nether`. Keep the same connection for
settings, Login and play; see the [accepting example](../crates/bedrock-client-tokio/README.md#accept-a-client).
NetherNet Login uses the peer's verified SDP key and DTLS protection.

## Connect through Player Messaging

Move your account's protected SDK socket into `PreparedMessaging` with the local
NetherNet ID and intended Player Messaging UUID. `recipient()` retains that route.

`connect` takes the proof-key SDP identity, explicit answer trust and setup
deadline. It keeps the acquired TURN expiry and makes one attempt. Every answer
requires signed identity and must pass verification. Offer completion requires a
peer receipt.

Poll `MessagingConnection::recv`, or `maintain` while application input is full.
Maintenance advances service control, heartbeats, receipts and late ICE without
consuming game data or creating another payload queue. Envelope UUID and
connection ID route signals; receipts follow bounded transport admission.
Cancellation does not retry an ambiguous admitted write. Service failure retires
the transport and returns one terminal after accepted reliable input.

`begin_close` ends local sending and returns `ClosingMessagingConnection` with
accepted input and terminal state. Existing sender clones observe closure too.
Drain before `try_finish`. Borrowed waits retain pending work across cancellation;
local close does not acknowledge remote processing.

## Accept through Player Messaging

Move the upgraded socket and local network ID into `PreparedMessagingServer`.
Call `bind` with connection and signaling configuration, setup deadline, answer
signer and offer trust. Poll `accept` for established NetherNet sessions and
`maintain` beside peer I/O when not accepting. This establishes transport; Login,
world publication and player authorization remain separate application work.

Supply `ServerIceConfig`. New offers check its TURN expiry; `set_server_ice`
affects later offers, not existing allocations. The default requires SDP identity.
`ConnectionConfig::allow_anonymous_offers` can permit absent assertions, but every
present assertion still passes the selected trust and fingerprint checks. This
setting does not authorize Minecraft Login.

An accepting JSON-RPC server can acquire fresh TURN credentials through
`begin_turn_refresh(deadline)` and `finish_turn_refresh(&receipt)`. Keep that
server's receipt across canceled waits. Finish it, retire it with
`cancel_turn_refresh`, or close the server before abandoning it. Canceling the
local wait does not undo a service write; late responses are ignored. A successful
result transfers credentials once with their acquired expiry. It does not refresh
account authentication, install ICE settings or renew existing allocations.

Coordinate `set_identity`, `set_token_trust` and `set_server_ice` before accepting
the next offer. Existing and pending sessions retain their transport and signer;
these setters perform no service request or atomic renewal.

`begin_close` seals service routes and returns `ClosingMessagingServer`. Keep
calling `finish_close` to close the WebSocket and join the listener, then consume
`try_finish`. Previously accepted sessions stay with their callers. Canceling a
borrowed close wait retains the listener and deadline; dropping the whole value
abandons that wait.

## Tokio packet sends and cancellation

Construct `Connection` with batch, generated packet-field and deferred-byte
limits. An incoming-only decoded ceiling takes effect when compression is
installed. Raw reads preserve header bits and bytes. A malformed later header is
reported after already accepted packets. Unknown packet handling and application
field validation remain your policy.

`AcceptingConnection::prepare_packets` and `prepare_raw` encode output once.
Keep calling `PreparedSend::next`; after each capacity wait, check current
authorization and call `commit` without an intervening await. Call `finish` after
the effect completes. A canceled
borrow can resume with `resume_send`; do not prepare the same effect again.

Keep pending settings, exchange and chunk states until the corresponding send
finishes. On failure, `begin_send_retirement` seals new commits and settles
committed output under the cleanup cutoff. Then `begin_close` returns a
receive/finish-only `RetiredAcceptingConnection` with the same input queue.

`PacketIo::close` ends sending while retaining accepted input. Once your
application has finished reading game data, `PacketIo::finish_close` on
`Connection` drives transport cleanup under its existing deadline. It does not
clear already decoded packets, and a canceled wait retains the closing transport.
Other `PacketIo` implementations default to calling their existing `close`.
RTT observations disappear when their transport retires. `WireIdentity` and the
challenge are metadata, not authentication or membership proof.
