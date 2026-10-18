# bedrock-client

Caller-driven Bedrock client negotiation using protocolgen's generated packets.
The cores create no runtime, socket, HTTP client, task, thread or clock. A caller
can drive many sessions from a shared event loop or use its preferred I/O edge.

`handshake::ClientHandshake` takes ownership of the caller's connection proof
key. Borrow `key()` for identity-aware transport admission; the same owner signs
Login and verifies the server exchange. Signed transports that retain the key can
pass an `Arc<SigningKey>` shared with their signing identity; owned keys also move
directly into the constructor. Both forms use one underlying key allocation.
Start negotiation, then apply each effect:

1. Send `start()` without compression.
2. On `Compression`, install the settings on the retained batch codec. Build
   application metadata, then call `login_offline` or `login_authenticated` and
   send that generated Login. UTC is explicit for offline signing. Account
   verification and credential deadline checks remain with the caller.
3. On `KeyExchange`, install both directional ciphers before encoding or sending
   the acknowledgment. A transport already providing application encryption can
   disable the additional batch cipher; the server token is still verified.
4. Send `Send` responses immediately. On `Packs`, send the optional cache status
   before starting the returned `packs::PackNegotiation`.

Retain decoded siblings in their original FIFO across codec transitions. Retain
the same ciphers for the connection and never discard ciphertext after advancing
the outgoing stream. The byte-oriented codec and directional ciphers remain in
`bedrock-net`; this crate does not add a second transport or batch implementation.

`packs::PackNegotiation` accepts optional caller-validated cache/CDN archives
before `start`, produces bounded chunk requests, verifies in-band SHA-256, and
returns owned archives in final server-selected stack order. Route its unhandled
packets through the retained handshake to handle late LoginSuccess or server key
exchange. Cache writers must release shared archive references before the final
stack. Handle Disconnect and Transfer at the application boundary.

After packs, drive `spawn::SpawnNegotiation` with a caller-selected
`RequestChunkRadius`. It emits that request exactly once after StartGame, hands
the first StartGame and item registry to application preparation as soon as both
arrive, and waits for the radius response and PlayerSpawn. Retain each returned
`deferred` packet in a bounded FIFO ahead of unread input. Terminal Disconnect or
Transfer packets require immediate caller handling. After `ready`, enter play;
call `finish_loading` once presentation is ready and send the initialization
acknowledgment. Loading-screen notifications, rendering limits and preparation
scheduling remain application policy.

Raw packet readers can pass only non-prerequisite IDs to `receive_deferred`
and retain their original bytes. This preserves lazy play decoding, including
terrain data, while the core remains the owner of startup terrain classification.
StartGame, ItemRegistry, PlayStatus and ChunkRadiusUpdated require their actual
decoded bodies through `receive`.

Deadlines, cancellation, malformed-wire handling, endpoint and account trust,
credential persistence, cache/CDN I/O, deferred byte bounds and ongoing play are
caller responsibilities. These owners do not claim live-server qualification.
Packet schemas and codecs remain in protocolgen. The extracted Cinnabar
implementation retains its [PolyForm Noncommercial license](../../LICENSE-CINNABAR);
the spawn adaptation preserves [Jolyne's MIT notice](LICENSE-AXOLOTL).
