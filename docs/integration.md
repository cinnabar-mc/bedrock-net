# Integrating the libraries

For a Tokio application, start with
[`bedrock-client-tokio`](../crates/bedrock-client-tokio). It connects the generated
packet codec to RakNet or NetherNet and drives settings, Login and pack transfer.
The [probe](../examples/client/src/main.rs) is a small client that uses these APIs.

For another runtime, use [`bedrock-client`](../crates/bedrock-client) and drive
its states from your existing network loop. It takes generated packets and
returns packets to send, configuration changes, or the next negotiation state.
It performs no socket, HTTP, filesystem or clock I/O. Supply time where requested.

## Keep one connection

Keep the same transport, batch codec, cipher streams and proof key throughout a
connection. Preserve unread packets when moving from settings to Login, packs,
startup and play. A new negotiation state does not create a new connection.

1. Decode a received batch once, then process its packets in order.
2. Feed packets to the active negotiation state. Handle terminal packets promptly
   and keep unrelated packets in a queue with an explicit byte limit.
3. Send returned packets in order. Complete any required flush and codec change
   before advancing a pending settings, key-exchange or chunk state.
4. Read queued packets before later network input, including after a phase change.

The Tokio `Connection` maintains the codec, ciphers and unread/deferred packet
queues for you. Construct it with batch limits, generated receive limits and a
deferred-byte budget for your application. See the
[connection implementation](../crates/bedrock-client-tokio/src/connection.rs) and
[transport setup example](../examples/client/src/transport.rs).

## State changes and errors

Negotiation methods often consume their current state and return the next one.
For example, a client settings response returns `ClientLoginReady`, which can
create Login. This prevents sending Login through a state still waiting for
settings.

Some errors return the state through `into_parts`. A local preparation failure
may allow correction and retry; a failed remote protocol transition ends that
negotiation. Retire the connection on terminal errors. Recovering a state does
not reset a deadline or cipher stream.

Keep pending states outside I/O futures that you may cancel. Dropping a future
that owns a state drops that state too. Borrowed waits preserve work only as
documented by their transport adapter; cancellation cannot undo admitted output.

## Time and authorization

Use one absolute setup deadline across the operation. Account credentials may
have a separate earlier expiry. Do not renew either cutoff when a packet arrives
or a capacity wait is canceled.

Successful cryptographic verification and application authorization are separate
steps. The server's authorization callback returns a grant that travels with the
session. Recheck that grant after waits, before actual packet admission and before
attaching a player to a world. Client credential checks also belong at transport
admission, after any capacity wait.

## Next steps

| Task | Guide |
| --- | --- |
| Encode batches, choose limits or install ciphers | [Batch framing](batches.md) |
| Sign Login, download packs and initialize a client | [Client negotiation](client.md) |
| Verify Login, serve packs and initialize a player | [Server negotiation](server.md) |
| Connect, maintain or close a transport | [Transports](transports.md) |
| Parse JSONC or consume archive handoffs | [bedrock-packs](../crates/bedrock-packs) |
