# bedrock-client

Client and server negotiation for Minecraft Bedrock, driven one packet at a time.
Use it with your own transport and scheduler, or use
[`bedrock-client-tokio`](https://github.com/cinnabar-mc/bedrock-net/blob/dev/crates/bedrock-client-tokio/README.md) for Tokio network adapters.

This crate handles settings, Login, resource packs and startup. It uses
protocolgen's generated packet types and performs no socket, HTTP, filesystem or
clock I/O. Your application sends the returned packets and supplies time,
credentials, authorization, pack storage and world data.

## Install

For the example below, add these direct dependencies:

```toml
[dependencies]
bedrock-client = { git = "https://github.com/cinnabar-mc/bedrock-net", branch = "dev" }
bedrock-protocol = { package = "bedrock-protocol-contract-1-26-60", git = "https://github.com/cinnabar-mc/protocolgen", rev = "9eed056998235e4c01e0f3befabed651021dea77" }
p384 = { version = "0.14", default-features = false, features = ["alloc", "ecdsa", "ecdh", "pkcs8"] }
```

The packet and key requirements match this crate's [workspace manifest](https://github.com/cinnabar-mc/bedrock-net/blob/dev/Cargo.toml).
Keep dependencies from this repository on one revision and commit `Cargo.lock`.

## Start a client

Give `ClientHandshake` the P-384 key used for this connection. It can share an
`Arc<SigningKey>` with account authentication or signed transport setup:

```rust
use bedrock_client::handshake::{ClientHandshake, ClientSettings, HandshakeError, HandshakeOptions};
use bedrock_protocol::packets::RequestNetworkSettings;
use p384::ecdsa::SigningKey;

fn start_client(
    key: SigningKey,
) -> Result<(ClientSettings, RequestNetworkSettings), HandshakeError> {
    ClientHandshake::new(key, HandshakeOptions::default())?.start()
}
```

Drive the returned states in this order:

| State | What to do |
| --- | --- |
| `ClientSettings` | Call `receive` until `SettingsEvent::Ready`; install its compression settings. |
| `ClientLoginReady` | Build metadata, then call `login_authenticated` or `login_offline` and send Login. |
| `ClientLogin` | Call `receive`; send responses and install any verified key-exchange ciphers. |
| `ClientPackOffer` | Supply validated preloads if available, then call `start`. |
| `ClientPacks` | Transfer packs until `PackComplete`; send each returned response. |
| `SpawnNegotiation` | Process startup packets and prepare presentation from the returned definitions. |
| `SpawnReady` | Once presentation is ready, call `finish_loading` and send its acknowledgment. |

Each transition consumes the old state and returns the next one. Keep unrelated
packets and unread batch entries in order; handle Disconnect and Transfer promptly.
A server may send `StartGame` without offering packs. In that case, Login returns
the startup packet directly for the same startup checks.

The [client guide](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/client.md) covers Login formatting, key exchange,
pack validation, early stack packets and startup. The
[probe](https://github.com/cinnabar-mc/bedrock-net/blob/dev/examples/client/src/main.rs) shows these states through the Tokio
adapter.

## Accept a client

Start with `server::ServerHandshake`, using your server key, settings and an
absolute deadline. Supply a `bedrock_net::login::LoginVerifier` configured for your
provider. For a local application that explicitly permits offline identities,
use `ServerHandshake::new_offline` with `OfflinePolicy`; account claims remain
untrusted on that path.

| Stage | What your application supplies |
| --- | --- |
| Settings | Send the plaintext response, enable compression, then call `flushed`. |
| Login | Verify the request and authorize the player through `VerifiedLogin::authorize`. |
| Key exchange | Fresh salt; flush the server token before installing its ciphers. |
| Packs | The selected world's `ServerPackSnapshot` and archive sources. |
| Startup | The selected world's generated definitions and radius policy. |
| Accepted session | Recheck authorization and attach the player to the running world. |

You may stop at `AcceptedLogin` or continue through `AcceptedSession`. Relay paths
observe an upstream world's startup without generating replacement world data.
See the [server guide](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/server.md) for each transition and the
[Tokio accepting example](https://github.com/cinnabar-mc/bedrock-net/blob/dev/crates/bedrock-client-tokio/README.md#accept-a-client) for I/O.

## Integration rules

Keep one key, codec and cipher pair for the connection. Send effects in order,
preserve unread packets across state changes, and keep the original deadline.
Check credentials and application authorization after I/O waits, before admission.
The [integration guide](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/integration.md) explains buffering, cancellation
and error handling; the [batch guide](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/batches.md) covers the byte layer.

## License

This crate is [MIT licensed](https://github.com/cinnabar-mc/bedrock-net/blob/dev/crates/bedrock-client/LICENSE-MIT). The spawn adaptation
also preserves [Jolyne's MIT notice](https://github.com/cinnabar-mc/bedrock-net/blob/dev/crates/bedrock-client/LICENSE-AXOLOTL).
The built-in pack catalog preserves
[Gophertunnel's MIT notice](https://github.com/cinnabar-mc/bedrock-net/blob/dev/crates/bedrock-client/LICENSE-MIT-gophertunnel).
