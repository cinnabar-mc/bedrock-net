use super::*;
use bedrock_client::handshake::{ClientHandshake, HandshakeOptions};
use bedrock_client_tokio::connection::Connection;
use bedrock_net::{BatchCodec, BatchHeader, BatchLimits, DecodeOutcome};
use bedrock_protocol::{
    packets,
    wire::{PacketHeader, Peer, Reader},
};
use bytes::Bytes;
use raknet::prelude::{
    Established, RakClock, RakServer, RakServerConfig, RakServerInput, RakServerOutput, RakSession,
    RakSessionInput, RakSessionOutput, Sans,
};
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;

/// One actual public serving endpoint, handing off its genuine negotiated session on the same socket.
struct ProbePeer {
    socket: UdpSocket,
    server: RakServer,
    session: Option<RakSession<Established>>,
}

impl ProbePeer {
    /// Binds only loopback and constructs the public endpoint from its actual local address.
    async fn new() -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let now = tokio::time::Instant::now().into_std();
        let server = RakServer::new(
            RakServerConfig::default(),
            socket.local_addr().unwrap(),
            RakClock::new(now),
            now,
        )
        .unwrap();
        Self {
            socket,
            server,
            session: None,
        }
    }

    /// Processes actual received datagrams through the same public endpoint/session route.
    async fn receive(&mut self) {
        let mut buffer = vec![0; usize::from(u16::MAX) + 1];
        let (length, from) = self.socket.recv_from(&mut buffer).await.unwrap();
        self.server
            .handle(RakServerInput::Datagram(
                buffer[..length].into(),
                from,
                tokio::time::Instant::now().into_std(),
            ))
            .unwrap();
    }

    /// Emits original protocol output and returns only genuine completed application messages.
    async fn drain(&mut self) -> Option<Bytes> {
        while let Some(output) = self.server.poll() {
            match output {
                RakServerOutput::SocketDatagram(bytes, to) => {
                    assert_eq!(self.socket.send_to(&bytes, to).await.unwrap(), bytes.len());
                }
                RakServerOutput::SessionConnected(session) => {
                    assert!(self.session.replace(session).is_none());
                }
                RakServerOutput::SessionDatagram(bytes, id) => {
                    let session = self.session.as_mut().expect("actual negotiated session");
                    assert_eq!(session.id(), id);
                    session
                        .handle(RakSessionInput::Datagram(
                            bytes,
                            tokio::time::Instant::now().into_std(),
                        ))
                        .unwrap();
                }
                RakServerOutput::SessionClosing(_) => panic!("probe peer closed before admission"),
            }
        }
        if let Some(session) = self.session.as_mut() {
            session
                .tick(tokio::time::Instant::now().into_std())
                .unwrap();
            while let Some(output) = session.poll() {
                match output {
                    RakSessionOutput::Datagram(bytes, to) => {
                        assert_eq!(self.socket.send_to(&bytes, to).await.unwrap(), bytes.len());
                    }
                    RakSessionOutput::Packet(bytes) => return Some(Bytes::from(bytes)),
                    RakSessionOutput::Wait(_) => {}
                    RakSessionOutput::Disconnected(..) => {
                        panic!("probe peer disconnected before its request")
                    }
                }
            }
        }
        None
    }

    /// Completes the actual public handshake without fabricating a connected owner.
    async fn establish(&mut self) {
        loop {
            assert!(self.drain().await.is_none());
            if self.session.is_some() {
                return;
            }
            self.receive().await;
        }
    }

    /// Awaits one real reliable message, without polling the probe again.
    async fn next_packet(&mut self) -> Bytes {
        loop {
            if let Some(packet) = self.drain().await {
                return packet;
            }
            self.receive().await;
        }
    }
}

/// A completed probe send must emit its generated packet before returning a typed continuation.
#[tokio::test]
async fn generated_probe_send_emits_without_a_later_receive_or_close() {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let mut peer = ProbePeer::new().await;
        let address = peer.socket.local_addr().unwrap();
        let (transport, ()) = tokio::join!(connect("raknet", address), peer.establish());
        let (transport, key) = transport.unwrap();
        let configured = ClientHandshake::new(key, HandshakeOptions::default()).unwrap();
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
        // The probe is deliberately not polled again: this tests its actual completed-send boundary.
        let message = tokio::time::timeout(std::time::Duration::from_secs(1), peer.next_packet())
            .await
            .expect("completed probe send retained its packet until a later receive or close");
        let DecodeOutcome::Packets {
            packets: mut frames,
            ..
        } = BatchCodec::new(BatchHeader::RakNet, BatchLimits::default())
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
    })
    .await
    .unwrap();
}
