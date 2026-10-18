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

Accepting Login uses its own consumed capabilities:

| Owner | Available work | Next owner |
| --- | --- | --- |
| `ServerHandshake` | Observe the actual settings request | `PendingServerSettings` |
| `PendingServerSettings` | Dispatch/flush plaintext and install compression | `ServerLogin` |
| `ServerLogin` | Verify actual provider/client/transport proof | `VerifiedLogin` |
| `VerifiedLogin` | Run explicit caller authorization | `ApprovedLogin<Grant>` |
| `ApprovedLogin<Grant>` | Revalidate and create the sole exchange | Pending exchange or `ServerPacksReady<Grant>` |
| `PendingServerKeyExchange<Grant>` | Flush plaintext; transfer exact cipher streams | `ServerAcknowledgment<Grant>` |
| `ServerAcknowledgment<Grant>` | Observe actual encrypted acknowledgment | `ServerPacksReady<Grant>` |
| `ServerPacksReady<Grant>` | Revalidate and consume the original Login/grant | `AcceptedLogin<Grant>` |

Supply one server key, original absolute deadline, any caller-verified transport
peer key and required `bedrock_net::login::LoginVerifier`. The verifier uses the
existing configured provider authority: signature, issuer, audience, dates, XUID
and `cpk`; there is no default or permissive verifier. Only actual verification
creates `VerifiedLogin`. Modern authenticated Login is supported; accepting legacy
chains, offline and guest authentication remain unimplemented.

`VerifiedLogin::authorize` runs the caller's actual policy callback against the
original authenticated player and signed nonce, retaining its concrete grant.
That grant is caller-trusted authority, not library-proven hosted membership.
For hosted worlds, use the real current directory/world/account/proof owner;
service cards, invites, SDP and client metadata alone do not authorize a player.
Recheck the grant after each wait before actual later dispatch/attachment.

Borrow the pending settings packet for uncompressed send/flush, install its
compression on the retained codec, then consume `flushed`. For encryption, provide
fresh caller-owned sixteen-byte salt, send/flush the pending server token in
plaintext, then consume its continuation and install both returned streams before
reading the encrypted acknowledgment. An explicitly encrypted transport skips the
additional cipher. Pending continuations have private constructors and retain the
exact output/owner on transition failure. They assert the adapter's explicit I/O
contract; a pure owner cannot prove a real socket flush. No unchecked Installed or
Approved marker constructor exists.

The original deadline never restarts. Provider identity/key/presentation are
revalidated at exchange, acknowledgment and final handoff. `ServerTransitionError`
returns the retained owner/cause for retirement; it never resets a failed owner.
No LoginSuccess or pack advertisement is emitted by this accepting milestone.
Prepare the actual world and exact pack snapshot before any later advertisement.
`AcceptedLogin` proves consumed Login completion, not world attachment/spawn.
The caller preserves decoded siblings, handles terminal packets immediately and
closes on failed transitions. No accepting listener, pack delivery or running-world
bridge is provided by this API.
