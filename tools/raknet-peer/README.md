# RakNet loopback peer

Build this small interoperability fixture from this directory:

```sh
go build -o ../../target/raknet-peer.exe .
```

It binds an ephemeral port on IPv4 loopback, writes its address to stdout, accepts
one connection, and echoes complete messages. `-close-after N` closes after N
messages. The Rust integration tests own and reap each fixture process.

Set `BEDROCK_NET_RAKNET_PEER` to the absolute executable path and run
`cargo test --locked -p bedrock-net --features raknet --test raknet`.
Without that fixture, the interoperability cases skip with a named missing-fixture
message; the socket cancellation/deadline tests still run. CI supplies the fixture.
