use super::*;
use bedrock_client::handshake::{ClientHandshake, HandshakeOptions};
use bedrock_client_tokio::connection::Connection;
use bedrock_net::{BatchCodec, BatchHeader, BatchLimits, DecodeOutcome};
use bedrock_protocol::{
    packets,
    wire::{PacketHeader, Peer, Reader},
};
use nethernet_tokio::{
    HttpServerConfig, HttpSignalingServer, NetherServer, ServerIceConfig, ServerIdentity,
};

/// A completed probe send emits its generated packet before another receive or close.
#[tokio::test]
async fn generated_probe_send_emits_without_a_later_receive_or_close() {
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    tokio::time::timeout_at(deadline, async {
        let signaling = Arc::new(
            HttpSignalingServer::bind("127.0.0.1:0".parse().unwrap(), HttpServerConfig::default())
                .await
                .unwrap(),
        );
        let address = signaling.local_addr();
        let mut listener = NetherServer::bind_with(
            Arc::clone(&signaling),
            ConnectionConfig {
                identity: Some(Arc::new(
                    ServerIdentity::from_key(
                        SigningKey::try_generate_from_rng(&mut SysRng).unwrap(),
                        "probe-fixture",
                        SystemTime::now(),
                        Some(HANDSHAKE_TIMEOUT),
                    )
                    .unwrap(),
                )),
                server_ice: Some(ServerIceConfig {
                    turn_streams: Vec::new(),
                    turn_tls: None,
                    ice: Default::default(),
                    bind_addr: "127.0.0.1:0".parse().unwrap(),
                }),
                attempts: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let (transport, peer) =
            tokio::join!(connect("nethernet", address, deadline), listener.accept(),);
        let (transport, key) = transport.unwrap();
        let mut peer = peer.unwrap();
        let configured = ClientHandshake::new(
            key,
            HandshakeOptions {
                batch_encryption: transport.batch_encryption(),
                ..Default::default()
            },
        )
        .unwrap();
        let (_settings, request) = configured.start().unwrap();
        let expected = request.client_network_version.0;
        let mut session = Connection::new(
            transport,
            BatchLimits::default(),
            bedrock_protocol::wire::Limits::receiving_from(Peer::Server),
            BatchLimits::default().max_decoded_bytes,
        );
        session
            .send_packet(&request.into(), Peer::Client, 0, 0)
            .await
            .unwrap();
        // Do not poll the probe again: its completed send must have emitted the packet.
        let message = tokio::time::timeout(std::time::Duration::from_secs(1), peer.reliable.recv())
            .await
            .expect("completed send retained its packet until a later receive or close")
            .unwrap()
            .unwrap();
        let DecodeOutcome::Packets {
            packets: mut frames,
            ..
        } = BatchCodec::new(BatchHeader::NetherNet, BatchLimits::default())
            .decode(message)
            .unwrap()
        else {
            panic!("generated probe request was not a valid batch");
        };
        assert_eq!(frames.len(), 1);
        let frame = frames.next().unwrap();
        let mut reader = Reader::from_shared(&frame);
        let header = PacketHeader::from_raw(reader.read_var_u32().unwrap());
        let packets::Packet::RequestNetworkSettings(request) =
            packets::Packet::decode_from(header.id, Peer::Client, &mut reader).unwrap()
        else {
            panic!("probe did not emit its original generated request");
        };
        assert_eq!(request.client_network_version.0, expected);
        assert_eq!(reader.remaining(), 0);
        session.transport_mut().finish_close().await.unwrap();
        let peer = peer.close();
        peer.session.closed().await;
        listener.close().await.unwrap();
        drop(listener);
        Arc::try_unwrap(signaling)
            .ok()
            .expect("HTTP signaling owner retired")
            .shutdown()
            .await;
    })
    .await
    .unwrap();
}
