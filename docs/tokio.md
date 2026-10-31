# Tokio client and server examples

Use these functions inside your application's Tokio session loop. Each function
shows all its inputs and return values; account credentials, player metadata and
the accepting listener come from your application.

## Dependencies

Add this complete block to a Rust 2024 application's `Cargo.toml`. It declares
every direct dependency used below, including the generated packet crate and
the accepting NetherNet session type:

```toml
[dependencies]
bedrock-client-tokio = { git = "https://github.com/cinnabar-mc/bedrock-net", branch = "dev", features = ["nethernet"] }
bedrock-client = { git = "https://github.com/cinnabar-mc/bedrock-net", branch = "dev" }
bedrock-net = { git = "https://github.com/cinnabar-mc/bedrock-net", branch = "dev" }
bedrock-protocol = { package = "bedrock-protocol-contract-1-26-60", git = "https://github.com/cinnabar-mc/protocolgen", rev = "9eed056998235e4c01e0f3befabed651021dea77" }
nethernet-tokio = { git = "https://github.com/cinnabar-mc/nethernet", rev = "ddd68ae2b4359eefdbc84f59ea82037563222c6c" }
p384 = { version = "0.14", default-features = false, features = ["alloc", "ecdsa", "ecdh", "pkcs8"] }
serde_json = { version = "1", features = ["raw_value"] }
tokio = { version = "1", features = ["rt", "time", "macros", "sync"] }
```

The registry requirements and external Git revisions match this workspace's
[Cargo.toml](../Cargo.toml) and the
[adapter manifest](../crates/bedrock-client-tokio/Cargo.toml). Keep crates from this
repository on one revision, commit your `Cargo.lock`, and use `rev` instead of
`branch` when you need manifest-level pins. The `raw_value` feature exposes the
client metadata type. Configure HTTP signaling, identity and server trust before
connecting; the same proof key must sign the transport offer and application Login.

## Connect a client

Supply a verified account token, its proof key and absolute credential expiry.
The metadata callback builds client claims after settings using your schema; the
[probe](../examples/client/src/main.rs) shows a concrete metadata builder.

```rust,no_run
use std::{error::Error, sync::Arc, time::{Duration, Instant}};
use bedrock_client::handshake::{ClientHandshake, ClientPackOffer, HandshakeOptions};
use bedrock_client_tokio::{connect, connection::Connection, transport::Transport, handshake::{self, LoginData}};
use nethernet_tokio::{ConnectionConfig, HttpSignaling};
use bedrock_net::BatchLimits;
use bedrock_protocol::wire::{Limits, Peer};
use p384::ecdsa::SigningKey;
use serde_json::value::RawValue;

async fn connect_client(
    signaling: HttpSignaling,
    endpoint: String,
    config: ConnectionConfig,
    key: Arc<SigningKey>,
    token: &str,
    credential_deadline: Instant,
    metadata: impl FnOnce(&Connection) -> Result<Box<RawValue>, Box<dyn Error>>,
) -> Result<(Connection, Option<ClientPackOffer>), Box<dyn Error>> {
    let deadline = (tokio::time::Instant::now() + Duration::from_secs(30))
        .min(credential_deadline.into());
    let ready = connect::http::connect(
        signaling, endpoint, config, deadline, Some(credential_deadline),
    ).await?;
    let transport = Transport::from_http(ready);
    let limits = BatchLimits::default();
    let configured = ClientHandshake::new(key, HandshakeOptions {
        ..Default::default()
    })?;
    let mut connection = Connection::new(
        transport, limits, Limits::receiving_from(Peer::Server),
        limits.max_decoded_bytes,
    );
    let (ready, settings) = tokio::time::timeout_at(
        deadline, handshake::settings(&mut connection, configured, &mut |_| {}),
    ).await??;
    println!("compression: {:?}", settings.algorithm);
    let claims = metadata(&connection)?;
    let input = LoginData::Authenticated {
        token, claims: &claims, deadline: credential_deadline,
    };
    let offer = tokio::time::timeout_at(
        deadline, handshake::login(&mut connection, ready, input, &mut |_| {}),
    ).await??;
    Ok((connection, offer))
}

```

The function returns the connection and its pack offer. For `Some(offer)`,
`packs::acquire` uses your `PackIo` implementation for cache reads and writes.
`None` means `StartGame` is already queued because the server skipped packs.
Continue with the [client guide](client.md) for packs and startup. For offline
Login, use `LoginData::Offline` with an explicit identity and UTC. Keep subsequent
negotiation under the same setup deadline.

## Send and receive packets

After initialization, pass a generated packet from your gameplay code to this
client-side function:

```rust,no_run
use bedrock_client_tokio::connection::Connection;
use bedrock_protocol::{packets::Packet, wire::Peer};

async fn exchange(connection: &mut Connection, outgoing: &Packet) -> std::io::Result<()> {
    connection.send_packet(outgoing, Peer::Client, 0, 0).await?;
    let (header, incoming) = connection.next_packet().await?;
    println!("received packet {}: {:?}", header.id, incoming.id());
    Ok(())
}

```

Use `Peer::Server` when sending from a server. Raw reads and prepared raw sends
let a proxy retain original packet headers and bytes.

To forward complete batches, select only the packet bodies your application needs:

```rust,no_run
use bedrock_client_tokio::connection::Connection;
use bedrock_protocol::packets::SetTime;

async fn forward(source: &mut Connection, destination: &mut Connection) -> std::io::Result<()> {
    let batch = source.read_batch_raw(|id| id == SetTime::ID).await?;
    for packet in batch.packets() {
        if let Some(result) = &packet.decoded {
            match result {
                Ok(decoded) => println!("selected packet: {:?}", decoded.id()),
                Err(error) => eprintln!("selected decode failed: {error}"),
            }
        }
    }
    destination.send_batch_raw(batch.into_body(), None).await
}
```

Unselected bodies stay opaque. A selected decode error retains that packet's raw
bytes, so the application can choose whether to forward it. Raw reads bypass the
typed reader's header filters and do not apply negotiation or disconnect policy.
Raw sends preserve headers and identity fields and submit output immediately;
they do not wait for a later flush. Prepared raw sends use the same capacity and
retirement checks as typed sends. After packet-at-a-time reads, a raw batch contains
the unread remainder; replayed packets form a separate prefix batch.
Both endpoints must use the same generated protocol version.

`AcceptingConnection::prepare_raw` keeps its configured identity normalization.
For exact forwarding, use `connection_mut().prepare_packet_raw` instead.

Install a `PacketObserver` with `Connection::set_packet_observer` to observe a
copied set of packet IDs in both directions. Its synchronous callback borrows the
payload without its header, before body decoding. Copy the payload explicitly if
you need to keep it, and keep the callback short. Replaying input does not repeat
the observation.

## Accept a client

Pass an association returned by `nethernet_tokio::NetherServer::accept`. This
function answers settings and returns the connection ready to verify Login.
Supply your provider verifier, server key and setup deadline; it does not
independently authorize a player or start a world.

```rust,no_run
use std::{error::Error, sync::Arc, time::{Instant, SystemTime}};
use bedrock_client::server::{ServerHandshakeOptions, ServerLogin, ServerSettingsEvent};
use bedrock_client_tokio::server::AcceptingConnection;
use bedrock_net::{BatchLimits, login::LoginVerifier};
use p384::ecdsa::SigningKey;
use nethernet_tokio::AcceptedSession;

async fn accept_settings(
    accepted: AcceptedSession,
    key: Arc<SigningKey>,
    verifier: &impl LoginVerifier,
    deadline: Instant,
) -> Result<(AcceptingConnection, ServerLogin), Box<dyn Error>> {
    let (mut wire, mut handshake) = AcceptingConnection::from_nether(
        accepted, key, ServerHandshakeOptions::default(),
        BatchLimits::default().max_decoded_bytes, deadline,
    ).await?;
    loop {
        let packet = wire.receive(deadline).await?;
        match handshake.receive(packet, verifier, Instant::now(), SystemTime::now())? {
            ServerSettingsEvent::Settings(pending) => {
                let mut send = wire.prepare_packets(
                    vec![pending.packet().clone().into()], deadline,
                )?;
                while let Some(capacity) = send.next().await? {
                    capacity.commit()?;
                }
                send.finish()?;
                wire.compression_flushed(pending.compression())?;
                let login = pending.flushed(Instant::now())?;
                return Ok((wire, login));
            }
            ServerSettingsEvent::Unhandled { handshake: next, packet } => {
                wire.handle_unhandled(&packet)?;
                handshake = next;
            }
            ServerSettingsEvent::Refused(status) => {
                let mut send = wire.prepare_packets(vec![status.into()], deadline)?;
                while let Some(capacity) = send.next().await? {
                    capacity.commit()?;
                }
                send.finish()?;
                return Err(std::io::Error::other("unsupported protocol").into());
            }
        }
    }
}

```

For NetherNet, `AcceptingConnection::from_nether` takes an accepted association
and binds Login to its verified SDP key. DTLS protects the association. Supply the
server proof key used by signaling.

Continue with the [server guide](server.md) for verification, authorization, packs
and startup. After authorization, recheck the grant after each
`send.next().await` and immediately before `capacity.commit()`. Keep pending
protocol states until the matching send finishes.
