# Server negotiation

Start with the [accepted-session example](../crates/bedrock-client-tokio/README.md#accept-a-client).
An established transport supplies packet I/O. Your application then verifies
Login, authorizes the player and supplies its selected world's data.

## Verify and authorize Login

Create `ServerHandshake` with the server proof key, settings and an absolute
monotonic deadline. If the transport verified the peer's key, supply that key for
Login binding. Use a `LoginVerifier` configured for your provider's signatures,
issuer, audience, dates, XUID and proof key; there is no default verifier.

Drive these transitions in order:

| State or event | Action |
| --- | --- |
| `ServerSettingsEvent::Settings` | Send its packet uncompressed, flush, install compression, then call `flushed`. |
| `ServerLogin` | Feed packets to `receive` until `ServerLoginEvent::Verified`. |
| `VerifiedLogin` | Call `authorize` with the application's current player/world policy. |
| `ApprovedLogin` | Recheck the returned grant, then call `accept`. |
| `ServerApprovalEvent::KeyExchange` | Send the server token in plaintext, flush, call `flushed`, then install both ciphers. |
| `ServerAcknowledgment` | Receive the encrypted acknowledgment to obtain `ServerPacksReady`. |

An already encrypted transport can reach `ServerApprovalEvent::Ready` without an
additional batch cipher. Otherwise, supply fresh caller-generated sixteen-byte
salt to `accept`. Keep pending states until their exact send completes; only then
call `flushed` and install the corresponding configuration.

Authorization is separate from cryptographic verification. The callback returns
a grant that travels with the session. Consult your current account, session and
world policy; a service card, invite, SDP or client metadata alone does not grant
world access. Recheck the grant after waits, before packet admission and before
attaching the player. The original deadline never restarts.

Provider identity, proof key and signed player identity are revalidated during
exchange, acknowledgment and later handoffs. `TrustedIdentity::with_player_identity`
can retain a signed name, canonical UUID and PlayFab identifiers;
`AuthenticatedLogin::player_identity` borrows them. Missing fields stay absent.

`ServerPacksReady::finish` returns `AcceptedLogin` if you only need Login
completion. It sends no `LoginSuccess` or pack offer. Continue with `start_packs`
when the world and pack snapshot are ready.

## Explicit offline admission

Use `ServerHandshake::new_offline` with `OfflinePolicy::new` when your application
permits offline Login. Supply a cached address resolver as described below.
Authorization receives `OfflineLogin`, and that distinct type remains with packs,
startup and relay sessions. Treat its account and UUID claims as untrusted;
assign world identity through application policy.

For parsing without a session, `bedrock_net::login::parse_offline_request` takes
UTC, a byte limit and the same cached resolver. It returns signed metadata with
the signer and final exchange key.

This policy leaves modern identity signatures, expiry and audience unverified.
Legacy-chain checks run during parsing. Signed client data, final exchange-key
binding, cipher acknowledgment, authorization and the setup deadline still apply.
Wire guest mode 1 is unsupported.

## Serve resource packs

Call `ServerPacksReady::start_packs` with a `ServerPackSnapshot`, delivery bounds,
verifier and time. The snapshot contains the offer, stack and original archives
in offer order. Validation happens before returning `LoginSuccess` and the offer;
send those packets in order, then drive `ServerPacks::receive`:

| `ServerPackEvent` | Action |
| --- | --- |
| `Send { session, packets }` | Send every packet, then keep `session` for the next input. |
| `ReadChunk(read)` | Read its `archive_index`, `offset` and `byte_len` from the retained source; `supply` returns a pending chunk. |
| `Chunk(chunk)` | Send `packet`, then call `flushed`; send follow-up packets before reading more input. |
| `WorldReady(ready)` | Supply world definitions through `start_world`, or choose a relay path. |
| `Unhandled { session, packet }` | Handle terminals promptly and preserve other packets with the returned session. |

Memory content shares immutable compressed bytes. External content records the
prevalidated size and SHA-256 while your adapter retains the immutable file or
source lease. Read from that same source: the library checks exact chunk lengths
and the full external hash before returning the final fragment. It performs no
filesystem I/O and does not require a whole disk archive in memory.

A pending read or chunk holds the session until it finishes. Keep pipelined
packets in the existing bounded input queue. A chunk's flush may advertise the
next archive's `ResourcePackDataInfo`; send it before processing another request.
Recheck authorization after I/O waits. Delivery bounds and chunk indexing come
from the snapshot and configuration; the core adds no pacing delay.

## Start the world

After the final stack acknowledgment, call `ServerWorldReady::start_world` with
`ServerWorld`. Supply the selected world's generated `StartGame`, item and
creative definitions and radius policy; there is no default world.

Send the returned startup packets before feeding more input to `ServerSpawning`.
Radius negotiation and the matching runtime-ID initialization produce
`ServerInitialized`. Its `finish` revalidates the provider and returns
`AcceptedSession` with Login, the grant and observed cache/radius. Recheck the
grant before attaching that player to the running world.

Local snapshot-validation errors return Login readiness so you can correct the
snapshot before advertising it. Protocol failures return their retained state
and output through `ServerTransitionError::into_parts` or
`ServerSessionTransitionError::into_parts` for retirement. A failed state cannot
restart negotiation or reset its deadline.

## Relay an upstream world

Use `ServerWorldReady::relay_world` to observe upstream startup without generating
replacement world packets. Feed controls to `forward_server` or `forward_client`,
forward the original packet, then call `PendingServerRelay::flushed` after its
write finishes. Keep raw headers and unread siblings in order.

The relay checks startup, item, radius and spawn controls and the matching client
Initialized packet. It returns `AcceptedSession` after the final forward and
provider revalidation. Recheck application authorization at each write and final
attachment.

For an upstream that starts without packs, use
`ServerPacksReady::relay_without_packs`. Flush its pending `LoginSuccess` before
forwarding startup. It creates no pack offer, stack or acknowledgment; startup and
runtime-ID checks still apply.

## Signed client data and address resolution

`client_data()` decodes invalid UTF-8 using Go replacement rules;
`client_data_json_bytes()` retains the signed JSON bytes. The provider-bound
`signing_key()` and final signed `exchange_key()` are distinct. Transport binding
and cipher setup use the exchange key; provider revalidation retains the signer
and identity. Nonce aliases use the final non-null signed value.

Some colon-containing UDP addresses need a successful cached result from
`LoginVerifier::resolve_client_address`. A cache miss returns
`AddressResolutionRequired`; unknown hosts or services need a result too. The
callback must not block or perform network I/O. Match your application's resolver
environment.

Preflight the parser, collect misses and resolve them asynchronously under the
same admission deadline. Replay the request once the cache is ready, before
submitting it to the consuming server state; an engine error ends that transition.
Resolver-independent literals and HTTP URLs need no callback. Empty IPv6 zones
and nonstandard IP spellings use the resolver.

`RawClientData::validate` applies application title, version and presentation
policy to relay metadata. Accepting signed Login uses the wire-admission checks
above. These parsing adaptations retain the
[gophertunnel](../THIRD_PARTY_NOTICES.md#gophertunnel) and
[Go](../THIRD_PARTY_NOTICES.md#go-standard-library) notices.
