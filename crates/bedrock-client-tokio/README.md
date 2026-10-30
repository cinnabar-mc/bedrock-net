# bedrock-client-tokio

Tokio adapters for Minecraft Bedrock client and server connections. They combine
the generated packet codec with batching, encryption and ordered input buffering.

Use the `nethernet` feature for concrete connections, settings, Login
and pack-transfer helpers. Without it, the crate provides `PacketIo`,
errors and RTT observations. Your application supplies the runtime and drives
sessions; this crate does not spawn a session task. Underlying transports may
run their own workers.

## Install

For the client, server and packet examples, copy the complete
[dependency block](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/tokio.md#dependencies). It includes Tokio, client
and batch APIs, the generated packet crate, P-384 keys, raw JSON metadata and
`NetherNet`'s accepting types, with versions and Git revisions from this workspace.

Keep crates from this repository on the same revision and commit your
application's `Cargo.lock`. HTTP, LAN and Player Messaging connections all use
`NetherNet` associations.

## Connect a client

The [client function](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/tokio.md#connect-a-client) connects through HTTP signaling, negotiates settings and sends authenticated Login. Supply the
verified token, proof key, expiry and a metadata builder. It returns the same
connection and an optional pack offer for further negotiation.

The [probe](https://github.com/cinnabar-mc/bedrock-net/blob/dev/examples/client/src/main.rs) is a complete runnable application
with explicit offline Login. Continue with the [client guide](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/client.md)
for pack acquisition and startup.

## Send and receive packets

The [packet exchange function](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/tokio.md#send-and-receive-packets) shows
all imports, parameters and return values. Use `send_packet` and `next_packet`
after initialization. A proxy can use raw reads and prepared raw sends to retain
original headers and bytes.

## Accept a client

The [accepting function](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/tokio.md#accept-a-client) takes a session from
`NetherServer::accept`, answers settings and returns the connection ready to verify
Login. `AcceptingConnection::from_nether` binds Login to the verified
SDP key and uses the association's DTLS protection.

Continue with the [server guide](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/server.md) for player authorization,
pack delivery and world startup. Keep pending protocol states until their
matching send finishes. Once authorization exists, recheck its grant after each
capacity wait and immediately before synchronous send commit.

## Connection lifetime

Keep the same `Connection` through settings, key exchange and play. It retains
unread packets across phase changes. A canceled borrowed send can resume through
`resume_send`; do not encode and admit the same effect again. On failure, settle
pending output and retire that connection under your cleanup deadline.

See [transport setup and shutdown](https://github.com/cinnabar-mc/bedrock-net/blob/dev/docs/transports.md) for polling,
backpressure, cancellation and closing.

## License

This crate is [MIT licensed](https://github.com/cinnabar-mc/bedrock-net/blob/dev/crates/bedrock-client-tokio/LICENSE-MIT).
