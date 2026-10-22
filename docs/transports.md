# Transports

Choose RakNet for a UDP endpoint, NetherNet for a signaled association, or Player
Messaging when you already have its service socket. Your application supplies the
runtime, endpoint policy and account credentials.

## Features

These are features of the root `bedrock-net` crate:

| Feature | Adds |
| --- | --- |
| Default | Synchronous batches and directional ciphers. |
| `login` | Login formatting, accepting verification, exchange and client-data validation. |
| `provider-verification` | Configured issuer/JWK verification for Login and signed SDP; includes `login`. |
| `raknet` | The caller-polled Tokio `RakNetConnection` UDP driver. |
| `messaging` | Client and server adapters combining an SDK service socket with NetherNet. |

The separate `bedrock-client-tokio` crate has `raknet` and `nethernet` features.
They enable its concrete connections and negotiation helpers. Neither crate
starts a runtime. The root RakNet driver starts no task; underlying NetherNet
adapters use bounded transport workers.

## Connect with Tokio

`bedrock-client-tokio::connect` provides these entry points:

| Route | Function and inputs |
| --- | --- |
| RakNet | `raknet::connect_resolved`: resolved addresses, `RakNetOptions` and a deadline. |
| Directed LAN | `lan::connect_resolved` or `lan::connect_directed`: discovery addresses and `DirectedLanConfig`. |
| HTTP signaling | `http::connect`: prepared HTTP signaling, endpoint, configuration and expiry. |

The RakNet and LAN helpers select among the supplied addresses. They keep the
first deadline and credential cutoff and drop losing attempts. LAN configuration
includes identity, trust, advertisement selection and a nonce bound. HTTP setup
returns a Ready client so your application can approve a first-use key before
wrapping it in `Transport::from_http`. DNS, TLS clients, egress, local-world
eligibility and service authorization belong to the application.

For accepting connections, pass the established session to
`AcceptingConnection::from_raknet` or `from_nether`. Keep the same connection for
settings, Login and play; see the [accepting example](../crates/bedrock-client-tokio/README.md#accept-a-client).
NetherNet Login uses the peer's verified SDP key and DTLS protection; RakNet uses
the configured Bedrock batch exchange and cipher.

## Drive the root RakNet connection

`RakNetConnection::connect` negotiates transport and retains one Tokio UDP socket.
Poll `recv` or `maintain` for ACKs, retransmissions and pings. `queue_send` admits a
complete message; `flush` emits ready datagrams. `wait_send_capacity` also services
incoming traffic while waiting for send budget.

When application input is full, `maintain` retains accepted input and defers new
reliable messages. Drain the queue and terminal result through `recv`. One message
may wait outside the queue, but a message larger than the whole byte allowance
still fails. Use `RakNetOptions` for receive/send budgets, setup and close
deadlines and the local MTU cap.

The driver normalizes mapped IPv4 before choosing the socket family and keeps
scoped IPv6 routing on the socket. A per-attempt GUID comes from OS entropy and
stays stable for retries. Transport time is monotonic and separate from Login UTC.

To close, consume `begin_close` and retain its `ClosingRakNetConnection` even when
the transition reports an error. Call `finish_close` on that value; canceled
borrowed waits retain input, datagrams and the close deadline. Drain accepted
messages and the terminal result with `recv`. `try_finish` returns
`ClosedRakNetConnection` after that drain and socket release. Dropping the
connection releases the socket. Local completion does not prove peer delivery.

## Connect through Player Messaging

Move your account's protected SDK socket into `PreparedMessaging` with the local
NetherNet ID and intended recipient. Select the dialect from your acquired route:
`new` takes a Player Messaging UUID, while `new_legacy` takes a legacy string
recipient and matching SDK socket. `recipient()` preserves that distinction.

`connect` takes the proof-key SDP identity, explicit answer trust and setup
deadline. It keeps the acquired TURN expiry and makes one attempt. Both dialects
need signed identity and answer trust. Only the explicit legacy route can permit
a missing answer assertion; any present assertion must pass verification. Legacy
offer completion uses the service delivery result rather than a peer receipt.

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
authorization and call `commit` without an intervening await. Cipher progress
happens once at that commit. Call `finish` after the effect completes. A canceled
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
