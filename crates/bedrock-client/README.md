# bedrock-client

Caller-driven Bedrock negotiation over protocolgen's generated packets. The pure
owners create no runtime, socket, HTTP client, task, thread or clock. Applications
own actual I/O, deadlines, cancellation, account/world authority and presentation.

The public client capabilities are consumed at each handoff:

| Owner | Available work | Next owner |
| --- | --- | --- |
| `ClientHandshake` | Retain the original proof key; start once | `ClientSettings` |
| `ClientSettings` | Observe actual settings; preserve unrelated input | `ClientLoginReady` |
| `ClientLoginReady` | Format one offline or acquired-credential Login | `ClientLogin` |
| `ClientLogin` | Observe post-Login controls and verified exchange | `ClientPackOffer` |
| `ClientPackOffer` | Supply validated cache/CDN preloads; start once | `ClientPacks` |
| `ClientPacks` | Transfer packs and handle late Login controls | `PackComplete` |
| `SpawnNegotiation` | Observe first definitions, radius and PlayerSpawn | `SpawnReady` |
| `SpawnReady` | Consume one presentation-ready initialization | Generated acknowledgment |

`ClientHandshake::new` accepts the caller's owned signing key or an existing
`Arc<SigningKey>`. The same underlying key signs Login and verifies the server
exchange; signed transports share that allocation without copying private key
material. Key generation and its platform entropy source remain caller-owned.

`start` returns the uncompressed request and settings owner. `SettingsEvent::Ready`
returns actual negotiated compression and Login readiness. Install compression on
the same retained codec before constructing/sending Login. Formatting errors retain
Login readiness through `LoginPreparationError::into_parts`; no Login was dispatched.
The authenticated formatter preserves the acquired token but does not verify its
issuer/account/proof/expiry. The account owner checks those again immediately before
actual transport admission, including any capacity wait.

A `ClientKeyExchange` owns the verified streams, acknowledgment and continuation.
Move them with `into_parts`, install both directions, then send the acknowledgment
before reading through the continuation. Transports that already encrypt the
application stream omit the additional ciphers but still verify the server token.
This is an explicit adapter contract, not a claim that a pure packet owner proved
a real socket operation. Retain the same ciphers throughout the connection and
never discard outgoing ciphertext after advancing the stream.

The pack handoff retains the original late Login/key-exchange owner. Cache status
is sent at most once before transfer. `ClientPackOffer` admits caller-validated
preloads, then its consuming `start` removes preload permission. `ClientPacks`
handles both resource packets and late Login controls; it returns startup and
terminal input unchanged. The standalone `PackOffer`→`PackNegotiation` API reuses
the same bounded transfer implementation when no Login control is needed.

Actual final-stack processing creates `PackComplete`, which has no public
constructor. Send its original stack acknowledgment before entering startup.
`start_spawn` transfers the exact ordered archives and configures the startup
observer. `into_parts` supports callers stopping at the pack boundary. Ordinary
`ResourcePackHandoff`/archive inputs are data, not constructors for protocol
completion. Cache writers release shared archive references before the final stack.

Startup returns the first StartGame/item registry as soon as both arrive and
requests the caller-selected radius once. Preserve returned `deferred` packets
in the caller's bounded FIFO ahead of unread input; handle Disconnect, Transfer
and non-spawn PlayStatus promptly. Only actual radius/PlayerSpawn prerequisites
produce the non-cloneable `SpawnReady`. Retain it until presentation completes,
then consume `finish_loading` once. Loading-screen policy remains application-owned.

External Go/prepared handoff adapters may configure `SpawnNegotiation::new` directly.
That creates only a prerequisite observer and claims no Login, pack or world
authority; the actual incoming prerequisites must still produce readiness.
`receive_deferred` accepts only unrelated raw packet IDs, retaining a terrain fact
while the caller keeps original bytes. StartGame, ItemRegistry, PlayStatus and
ChunkRadiusUpdated require decoded bodies. Packet schemas/codecs remain in
protocolgen; the byte codec and directional ciphers remain in `bedrock-net`.

Malformed-wire handling, endpoint trust, credential persistence, cache/CDN I/O,
deferred byte bounds and ongoing play stay with callers. These APIs do not claim
live-server qualification. The extracted Cinnabar implementation retains its
[PolyForm Noncommercial license](../../LICENSE-CINNABAR); the spawn adaptation
preserves [Jolyne's MIT notice](LICENSE-AXOLOTL).

`server::ServerHandshake` provides the accepting network/Login half, ending before
pack preparation. Supply one server key, an absolute caller deadline, any verified
transport peer key and a required `bedrock_net::login::LoginVerifier`. Reuse the
existing configured provider verification owner; it must authenticate signature,
issuer, audience, dates, XUID and `cpk`. There is no default or permissive verifier.
Modern authenticated Login is supported; legacy chains, offline and guest admission
remain unimplemented.

Send and flush `NetworkSettings` uncompressed before installing compression and
calling `compression_installed`. `LoginVerified` pauses for application admission:
check the authenticated player's XUID and original signed nonce against the current
hosted session, world opening and host account binding. Then call `accept`. When
batch encryption is enabled, supply fresh caller-owned sixteen-byte salt, send and
flush the returned server token in plaintext, install both streams, then call
`encryption_installed` before reading the encrypted acknowledgment. Transports that
already encrypt the application stream can explicitly skip the extra batch cipher.

At `ReadyForPacks`, `finish` transfers the verified Login after revalidation. Prepare
the actual world connection and exact pack snapshot before sending LoginSuccess or
ResourcePacksInfo; recheck the original application approval after every wait before
the final handoff. Client metadata remains player-controlled despite its signature.
This module does not publish a world, implement server pack chunk delivery or bridge
a peer to a running world. The caller retains packet siblings, handles terminal
packets immediately, bounds admission/cleanup and closes on failed transitions.
