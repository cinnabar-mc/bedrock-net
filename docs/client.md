# Client negotiation

Start with the [Tokio example](../crates/bedrock-client-tokio/README.md#connect-a-client),
or drive `bedrock-client` from your own network loop. Keep one connection and its
proof key through Login, packs and startup.

## Settings and Login

1. Create `ClientHandshake` with your P-384 key or shared `Arc<SigningKey>`.
2. Call `start` and send its `RequestNetworkSettings` uncompressed.
3. Feed generated packets to `ClientSettings::receive`. `Pending` returns the
   settings state and unrelated input; `Ready` returns compression and
   `ClientLoginReady`.
4. Install compression before constructing metadata and formatting Login.
5. Call `login_authenticated` or `login_offline`, then send the returned Login.

Key generation, account acquisition and metadata construction belong to your
application. The authenticated formatter preserves the supplied token; check its
issuer, account, proof-key binding and expiry before actual transport admission,
including after any capacity wait. Use the same key for Login and signed transport.

Formatting errors return readiness so you can correct local input before sending:

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

`bedrock_protocol` is the workspace alias for the generated packet crate. Match
its declaration in [Cargo.toml](../Cargo.toml) when using these types.

## Process Login responses

Call `ClientLogin::receive` for each relevant packet. Send returned packets in
order. For `KeyExchange`, take the next state and acknowledgment with `into_parts`.
Send the acknowledgment before continuing input. The server token's signature,
public key, headers and salt encoding are verified.

`LoginEvent::Packs` returns the offer and optional cache status. Send the cache
status once. The offer retains the Login state so late key exchange or Login
controls can still be processed during pack transfer.

`LoginEvent::Startup` returns a `StartGame` received without an earlier pack
offer. Retain its encoded header and body ahead of unread siblings. Continue with
startup using that packet; no pack offer, stack or acknowledgment is created.

The Tokio helpers accept an `Observation` callback for received packets, unknown
headers and successfully sent effects. It borrows those values synchronously and
cannot replace packets or change admission.

Preserve unrelated packets in a byte-bounded queue. Handle Disconnect, Transfer
and refusal statuses promptly. A received-packet error ends negotiation; close
the same connection instead of replacing its handshake state.

## Download packs

`ClientPackOffer` accepts validated cache or CDN preloads before `start`.
`ClientPacks` then handles transfer and late Login controls. The standalone
`PackOffer` → `PackNegotiation` API uses the same transfer engine without Login.

`PackTransferLimits` defaults its archive count and byte caps to `None`; choose
explicit caps for your application. In-band transfer still validates lengths,
identity and SHA-256, and bounds the chunk-request window. Transfer has no cache
or HTTP client: your application performs storage and CDN reads.

Validate each preload's archive and manifest identity against its offer before
`supply_preloaded`. The offer contains no archive hash, so this call checks byte
bounds rather than authenticating content. In-band data is checked against its
`ResourcePackDataInfo` hash. The final stack's required bit controls rejection of
unavailable selected entries; the archive handoff retains the offer-or-stack
required policy.

Send each transfer response immediately. An early stack returns
`PacksEvent::DeferredStack` or `PackEvent::DeferredStack`. Keep it in your pending
queue while transfer continues. Once `ready_for_stack()` is true, release shared
cache-write references and replay the stack through `receive` before waiting for
more network input. Deferred stacks retain their fields without retaining
unrelated batch storage.

Processing the final stack returns `PackComplete`. `start_spawn` moves its
archives into a handoff and returns the stack acknowledgment and startup state.
Send the acknowledgment first. `into_parts` lets an application stop at the pack
boundary. Constructing a `ResourcePackHandoff` yourself does not complete protocol
negotiation.

## Initialize the player

Process every field of `SpawnUpdate`: send `request_radius`, prepare the world
from `startup`, preserve or handle `deferred`, and retain `ready` when returned.
The first `StartGame` and item registry become available together so application
loading can start while network negotiation continues.

`StartGame`, the first item registry and `PlayerSpawn` produce `SpawnReady`.
A radius reply may arrive later during play. Preserve deferred packets ahead of
unread input and handle terminal packets promptly. Once presentation is ready,
consume `finish_loading` once and send its initialization acknowledgment.

`SpawnNegotiation::new` also supports externally prepared pack handoffs, but it
still needs the incoming startup prerequisites. `receive_deferred` accepts only
unrelated raw packet IDs while you retain their original bytes. Decode bodies for
`StartGame`, `ItemRegistry`, `PlayStatus` and `ChunkRadiusUpdated`.

## Retain metadata for a relay

Call `ClientHandshake::retain_pack_metadata` or `PackOffer::new_with_metadata`
before acquisition when a relay needs offer and stack metadata.
`PackComplete::into_parts_with_metadata` returns it with the acknowledgment and
archive handoff. Offer entries keep offer order; stack entries keep application
order. Data-information packets stay aligned with offers. Preloaded archives
have no data-information packet, so their aligned entry is `None`. The ordinary
client path avoids these metadata copies.

`transfer::TransferTarget` normalizes decoded targets under the shared byte,
character and port bounds. Your application decides whether to resolve, authorize
or follow a target.
