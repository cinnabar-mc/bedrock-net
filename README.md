# bedrock-net

Build Minecraft Bedrock clients, servers and proxies in Rust. These libraries
handle Login, resource-pack transfer and session startup, with Tokio adapters
for `RakNet` and `NetherNet` connections.

## Connect to a server

Run the included client against a listening peer that permits offline Login:

```sh
git clone https://github.com/cinnabar-mc/bedrock-net
cd bedrock-net
cargo run --locked -p bedrock-probe -- raknet 127.0.0.1:19132 --offline-login
```

The probe connects, negotiates compression, sends Login with synthetic player
and skin data, and prints Login status. It stops at the pack offer, or at
`StartGame` if the peer skips packs. It does not download packs or enter a world.
Omit `--offline-login` to request settings only.

For an authenticated client, start with the
[connect and Login example](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/tokio.md#connect-a-client).
Supply your account token, its proof key, expiry and client metadata. Continue
with the [client guide](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/client.md) to download packs and initialize the player.
The [probe source](https://github.com/cinnabar-mc/bedrock-net/blob/dev/examples/client/src/main.rs) shows metadata construction and
connection cleanup.

The probe also supports HTTP signaling and directed LAN discovery:

```sh
cargo run --locked -p bedrock-probe -- nethernet 127.0.0.1:19132 --offline-login
cargo run --locked -p bedrock-probe -- nethernet-lan 127.0.0.1:19132 --offline-login
```

The LAN probe requires an IPv4 loopback discovery endpoint. See the
[transport guide](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/transports.md) for application setup and trust settings.

## Accept clients or build a proxy

Start a listener with [`raknet-tokio`](https://github.com/cinnabar-mc/raknet) and
pass an accepted session to `AcceptingConnection::from_raknet`. For `NetherNet`,
use `AcceptingConnection::from_nether`. The
[accepting example](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/tokio.md#accept-a-client) reads a
settings request, sends its response and prepares the connection for Login.

Your application supplies Login verification and player authorization. Then you
can serve a resource-pack snapshot and world definitions, or relay an upstream
server's startup. The [server guide](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/server.md) explains both paths and the
packets to send at each step. The library handles negotiation; your application
runs the world and ongoing gameplay.

For a proxy, retain original packet headers and forward packet bytes in order.
Use the [relay startup APIs](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/server.md#relay-an-upstream-world) to track
initialization and the [pack metadata option](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/client.md#retain-metadata-for-a-relay)
when you need the upstream offer and stack.

## Send and receive packets

After negotiation, keep the same `Connection` for play. `next_packet` returns a
generated packet with its header; `send_packet` sends a generated packet with
your selected sender role and subclient IDs. See the
[packet I/O example](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/tokio.md#send-and-receive-packets).
Raw reads and forwarding are available when a proxy must preserve packet bytes.

Packet types and codecs come from
[protocolgen](https://github.com/cinnabar-mc/protocolgen). Account authentication
and service requests come from
[bedrock-services](https://github.com/cinnabar-mc/bedrock-services).

## Add it to your application

For the client, server and packet examples, copy the complete
[Tokio dependency block](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/tokio.md#dependencies). It declares every direct
dependency and feature used by those functions, including the generated packet
crate and accepting `RakNet` types. The individual crate READMEs have setup for
their examples too.

Use Git dependencies while the required registry releases are unavailable.
Keep crates from this repository on one revision and commit `Cargo.lock`.
The [workspace manifest](https://github.com/cinnabar-mc/bedrock-net/blob/dev/Cargo.toml) declares the Rust version and external
revisions. Native DEFLATE encoding requires a C compiler.

| If you need… | Use |
| --- | --- |
| Connections on your Tokio runtime | [`bedrock-client-tokio`](https://github.com/cinnabar-mc/bedrock-net/blob/dev/crates/bedrock-client-tokio/README.md), with `raknet` or `nethernet`. |
| Negotiation on another runtime or an existing network loop | [`bedrock-client`](https://github.com/cinnabar-mc/bedrock-net/blob/dev/crates/bedrock-client/README.md). |
| Batching and encryption for encoded packets | [`bedrock-net`](https://github.com/cinnabar-mc/bedrock-net/blob/dev/src/lib.rs). |
| Pack JSONC parsing and archive handoffs | [`bedrock-packs`](https://github.com/cinnabar-mc/bedrock-net/blob/dev/crates/bedrock-packs/README.md). |

`bedrock-client` and `bedrock-packs` do no I/O and use no async runtime. The default
`bedrock-net` build is synchronous; its optional transports use Tokio.
`bedrock-client-tokio` uses your runtime and does not spawn a session task for you.
Underlying transports may run their own workers.

## Guides and reference

- [Integration](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/integration.md): packet routing, buffering, deadlines and errors.
- [Client](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/client.md): Login, packs and entering play.
- [Server](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/server.md): verification, authorization, packs and world startup.
- [Transports](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/transports.md): connection setup, polling and shutdown.
- [Batch codec](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/batches.md): framing, compression, limits and encryption.
- [Release dependencies](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/releases.md): packaging and registry prerequisites.

## License

The root crate is available under MIT or Apache-2.0. `bedrock-client`,
`bedrock-client-tokio` and `bedrock-packs` retain their
[PolyForm Noncommercial license](https://github.com/cinnabar-mc/bedrock-net/blob/dev/LICENSE-CINNABAR).
[NOTICE](https://github.com/cinnabar-mc/bedrock-net/blob/dev/NOTICE) and [THIRD_PARTY_NOTICES.md](https://github.com/cinnabar-mc/bedrock-net/blob/dev/THIRD_PARTY_NOTICES.md) list retained
implementation and dependency attribution.
