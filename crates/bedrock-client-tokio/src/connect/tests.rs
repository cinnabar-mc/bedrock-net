// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;
use bedrock_net::BatchHeader;
use bedrock_net::raknet::RakNetOptions;
use bytes::Bytes;
use lan::{DirectedLanConfig, LanSelection};
use nethernet_tokio::{ConnectionConfig, LanConfig, LanSignaling, NetherServer, ServerData};
use std::{
    net::{Ipv6Addr, SocketAddr},
    process::Stdio,
    time::Duration,
};
use tokio::time::Instant;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::UdpSocket,
    process::Command,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Excludes child fork/exec inheritance while the fixture checks physical socket retirement.
static CHILD_SPAWN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The original direct offline route admits a nonce but imposes no extra nonce cap.
fn offline_options() -> DirectedLanConfig {
    DirectedLanConfig {
        connection: ConnectionConfig {
            max_incoming_message_bytes: bedrock_net::BatchLimits::default().max_encoded_bytes,
            allow_unsigned_answers: true,
            attempts: 1,
            ..Default::default()
        },
        selection: LanSelection::SelfSigned,
        max_nonce_bytes: 0, // Not consulted by this original direct-offline mode.
        credential_expires: None,
    }
}

/// A real localhost answer remains usable when an unsupported IPv6 candidate precedes it.
#[tokio::test]
async fn native_lan_resolution_skips_ipv6_and_keeps_the_ready_ipv4_owner() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let signaling = LanSignaling::with_config(
            31,
            address,
            LanConfig {
                discovery_port: address.port(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let mut data = ServerData::new("Fixture".into(), "World".into());
        data.flag_b = true;
        data.session_id = "original-fixture-nonce".into();
        data.protocol_version = bedrock_protocol::PROTOCOL_VERSION as u32;
        signaling.set_server_data(data);
        let mut listener = NetherServer::bind_with(
            signaling,
            ConnectionConfig {
                allow_unsigned_answers: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let deadline = Instant::now() + TEST_TIMEOUT;
        let resolved = tokio::net::lookup_host(("localhost", address.port()))
            .await
            .unwrap();
        let addresses =
            std::iter::once(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), address.port()))
                .chain(resolved);
        let options = offline_options();
        let (connected, peer) = tokio::join!(
            lan::connect_resolved(addresses, &options, deadline),
            listener.accept(),
        );
        let mut connected = connected.unwrap();
        let mut peer = peer.unwrap();
        assert_eq!(connected.header(), BatchHeader::NetherNet);
        assert_eq!(connected.nonce(), "original-fixture-nonce");
        peer.session
            .send(Bytes::from_static(b"same peer"))
            .await
            .unwrap();
        assert_eq!(connected.recv().await.unwrap(), "same peer");
        connected
            .send_until(Bytes::from_static(b"same client"), None)
            .await
            .unwrap();
        assert_eq!(peer.reliable.recv().await.unwrap().unwrap(), "same client");
        connected.close().await.unwrap();
        let retired = peer.close();
        retired.session.closed().await;
        listener.close().await.unwrap();
    })
    .await
    .expect("finite IPv4 LAN resolution fixture stalled");
}

/// Discovery retains its own socket while ICE uses the caller's exact nonzero bind.
#[tokio::test]
async fn native_lan_discovery_preserves_the_configured_ice_port() {
    let _spawn = CHILD_SPAWN.lock().await;
    tokio::time::timeout(TEST_TIMEOUT, async {
        let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = reservation.local_addr().unwrap();
        let client_reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_address = client_reservation.local_addr().unwrap();
        drop(reservation);
        let signaling = std::sync::Arc::new(
            LanSignaling::with_config(
                32,
                address,
                LanConfig {
                    discovery_port: address.port(),
                    ..Default::default()
                },
            )
            .await
            .unwrap(),
        );
        let mut data = ServerData::new("Fixture".into(), "World".into());
        data.flag_b = true;
        data.session_id = "original-fixture-nonce".into();
        data.protocol_version = bedrock_protocol::PROTOCOL_VERSION as u32;
        signaling.set_server_data(data);
        let mut listener = NetherServer::bind_with(
            std::sync::Arc::clone(&signaling),
            ConnectionConfig {
                allow_unsigned_answers: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let mut options = offline_options();
        options.connection.client_ice = Some(nethernet_tokio::ClientIceConfig {
            turn_streams: Vec::new(),
            turn_tls: None,
            ice: Default::default(),
            bind_addr: Some(client_address),
        });
        drop(client_reservation);
        let deadline = Instant::now() + TEST_TIMEOUT;
        let (mut connected, mut peer) = {
            let connecting = lan::connect_directed(address, &options, deadline);
            let accepting = listener.accept();
            tokio::pin!(connecting, accepting);
            tokio::select! {
                result = &mut connecting => {
                    let peer = if result.is_ok() { Some(accepting.await) } else { None };
                    (result, peer)
                }
                peer = &mut accepting => (connecting.await, Some(peer)),
            }
        };
        let exchange: io::Result<_> = async {
            let (connected, _) = connected.as_mut().map_err(|error| {
                io::Error::new(error.kind(), "configured ICE connection did not complete")
            })?;
            let peer = peer
                .as_mut()
                .ok_or_else(|| io::Error::other("original LAN peer was not accepted"))?
                .as_mut()
                .map_err(|_| io::Error::other("original LAN listener failed"))?;
            peer.session
                .send(Bytes::from_static(b"configured peer"))
                .await
                .map_err(io::Error::other)?;
            let inbound = connected.recv().await?;
            connected
                .send_until(Bytes::from_static(b"configured client"), None)
                .await?;
            let outbound = peer.reliable.recv().await.map_err(io::Error::other)?;
            Ok((
                inbound,
                outbound,
                peer.session.remote_addr().await.socket_addr,
                connected.header(),
                connected.nonce().to_owned(),
            ))
        }
        .await;
        let close = match &mut connected {
            Ok((connected, _)) => connected.close().await,
            Err(_) => Ok(()),
        };
        let peer_close: io::Result<()> = async {
            if let Some(Ok(peer)) = peer.take() {
                let mut retired = peer.close();
                while retired
                    .reliable
                    .recv()
                    .await
                    .map_err(io::Error::other)?
                    .is_some()
                {}
                while retired
                    .unreliable
                    .recv()
                    .await
                    .map_err(io::Error::other)?
                    .is_some()
                {}
            }
            Ok(())
        }
        .await;
        listener.close().await.unwrap();
        drop(listener);
        std::sync::Arc::try_unwrap(signaling)
            .ok()
            .expect("original signaling owner retired")
            .shutdown()
            .await;
        let connected = connected.map(|_| ());
        let _client_released = UdpSocket::bind(client_address)
            .await
            .expect("original configured ICE socket retired");
        let _server_released = UdpSocket::bind(address)
            .await
            .expect("original discovery socket retired");
        close.unwrap();
        peer_close.unwrap();
        connected.expect("directed LAN must establish with the original configured ICE bind");
        let (inbound, outbound, remote, header, nonce) = exchange.unwrap();
        assert_eq!(inbound, "configured peer");
        assert_eq!(outbound, Some(Bytes::from_static(b"configured client")));
        assert_eq!(remote, Some(client_address));
        assert_eq!(header, BatchHeader::NetherNet);
        assert_eq!(nonce, "original-fixture-nonce");
    })
    .await
    .expect("finite configured ICE LAN fixture stalled");
}

/// The actual pending RakNet socket is dropped on either cancellation or the original cutoff.
#[tokio::test]
async fn native_candidate_cancellation_and_original_deadline_release_actual_sockets() {
    let _spawn = CHILD_SPAWN.lock().await;
    for expires in [false, true] {
        let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = blackhole.local_addr().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut connecting = Box::pin(raknet::connect_resolved(
            std::iter::once(address),
            RakNetOptions::default(),
            deadline,
        ));
        let mut datagram = [0; 2048];
        let (_, source) = tokio::select! {
            result = blackhole.recv_from(&mut datagram) => result.unwrap(),
            _ = &mut connecting => panic!("a silent loopback peer completed a handshake"),
        };
        if expires {
            tokio::time::pause();
            tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
            assert_eq!(
                connecting.await.err().unwrap().kind(),
                io::ErrorKind::TimedOut
            );
        } else {
            drop(connecting);
        }
        let _released = UdpSocket::bind(source)
            .await
            .expect("original candidate socket retired");
    }
}

/// Reuses the library's real bounded Go peer, while a first live UDP endpoint stays silent.
#[tokio::test]
async fn native_raknet_alternative_progresses_past_a_silent_first_endpoint() {
    let Some(binary) = std::env::var_os("BEDROCK_NET_RAKNET_PEER") else {
        eprintln!("missing fixture: BEDROCK_NET_RAKNET_PEER; build bedrock-net tools/raknet-peer");
        return;
    };
    tokio::time::timeout(TEST_TIMEOUT, async {
        let mut child = {
            let _spawn = CHILD_SPAWN.lock().await;
            Command::new(binary)
                .args(["-close-after=0", "-ipv6=false"])
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .kill_on_drop(true)
                .spawn()
                .expect("start existing loopback RakNet fixture")
        };
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let peer: SocketAddr = lines.next_line().await.unwrap().unwrap().parse().unwrap();
        assert!(peer.ip().is_loopback());
        let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let deadline = Instant::now() + TEST_TIMEOUT;
        let resolved = tokio::net::lookup_host(("localhost", peer.port()))
            .await
            .unwrap();
        let addresses = std::iter::once(blackhole.local_addr().unwrap()).chain(resolved);
        let mut connected = raknet::connect_resolved(addresses, RakNetOptions::default(), deadline)
            .await
            .unwrap();
        assert_eq!(connected.header(), BatchHeader::RakNet);
        let message = Bytes::from_static(b"\xfefallback");
        connected.send_until(message.clone(), None).await.unwrap();
        assert_eq!(connected.recv().await.unwrap(), message);
        connected.close().await.unwrap();
        assert!(child.wait().await.unwrap().success());
    })
    .await
    .expect("finite alternative RakNet fixture stalled");
}

/// An empty compatible set cannot start LAN discovery or manufacture a transport owner.
#[tokio::test]
async fn native_lan_resolution_rejects_an_incompatible_candidate_set() {
    let addresses = [SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 19132)];
    let error = lan::connect_resolved(
        addresses.into_iter(),
        &offline_options(),
        Instant::now() + TEST_TIMEOUT,
    )
    .await
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
}
