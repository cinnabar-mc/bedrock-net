//! Actual loopback service framing and signed transport; no retail/account authority is asserted.

use super::*;
use bedrock_services::signaling::websocket::test_support;
use nethernet::identity::{ServerIdentity, TokenTrust};
use nethernet_tokio::{
    CallerServerSignaling, CallerServerSignalingConfig, CallerServerSignalingDriver, NetherServer,
    ServerIceConfig, SignalDelivery, SignalType,
};
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

/// The selected string route crosses the real SDK socket and both actual signed transport peers.
#[tokio::test]
async fn legacy_service_socket_establishes_signed_peer_and_retires_original_route() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let local = 7;
        let remote = "actual-service-network";
        let bind = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let (socket, peer) = test_support::pair_legacy(local).await;
        let prepared = PreparedMessaging::new_legacy(socket, local, remote.to_owned()).unwrap();
        assert!(matches!(prepared.recipient(), Recipient::Legacy(route) if route == remote));
        let (caller, server_service) =
            CallerServerSignaling::new(remote.to_owned(), CallerServerSignalingConfig::default())
                .unwrap();
        let mut server = NetherServer::bind_with(
            caller,
            ConnectionConfig {
                identity: Some(Arc::new(
                    ServerIdentity::generate("server.fixture.invalid", SystemTime::now()).unwrap(),
                )),
                token_trust: Some(TokenTrust::Any),
                server_ice: Some(ServerIceConfig {
                    ice: Default::default(),
                    bind_addr: bind,
                    turn_streams: Vec::new(),
                    turn_tls: None,
                }),
                max_sessions: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let application = async {
            let connected = prepared
                .connect(
                    ConnectionConfig {
                        identity: Some(Arc::new(
                            ServerIdentity::generate("client.fixture.invalid", SystemTime::now())
                                .unwrap(),
                        )),
                        server_trust: Some(TokenTrust::Any),
                        client_ice: Some(ClientIceConfig {
                            ice: Default::default(),
                            bind_addr: Some(bind),
                            turn_streams: Vec::new(),
                            turn_tls: None,
                        }),
                        ..Default::default()
                    },
                    deadline,
                )
                .await;
            let result = match connected {
                Ok(mut client) => match server.accept().await {
                    Ok(mut accepted) => {
                        let result = async {
                            client
                                .sender()
                                .send(Bytes::from_static(b"legacy visitor to host"))
                                .await
                                .map_err(|_| Error::Transport)?;
                            if accepted
                                .reliable
                                .recv()
                                .await
                                .map_err(|_| Error::Transport)?
                                .as_deref()
                                != Some(b"legacy visitor to host".as_slice())
                            {
                                return Err(Error::Transport);
                            }
                            accepted
                                .session
                                .send(Bytes::from_static(b"legacy host to visitor"))
                                .await
                                .map_err(|_| Error::Transport)?;
                            if client.recv().await?.as_deref()
                                != Some(b"legacy host to visitor".as_slice())
                            {
                                return Err(Error::Transport);
                            }
                            Ok(())
                        }
                        .await;
                        let sender = client.sender();
                        let mut closing = client.begin_close();
                        let terminal = closing.recv().await;
                        let locally_done = closing.try_finish().is_ok();
                        let retired = accepted.close();
                        // These observe shared closure, not accepted worker JoinHandles.
                        tokio::join!(sender.closed(), retired.session.closed());
                        result.and({
                            if locally_done && matches!(terminal, Ok(None)) {
                                Ok(())
                            } else {
                                Err(Error::Transport)
                            }
                        })
                    }
                    Err(_) => {
                        drop(client.begin_close());
                        Err(Error::Transport)
                    }
                },
                Err(error) => Err(error),
            };
            server.close().await.map_err(|_| Error::Transport)?;
            result
        };
        let service = service(peer, server_service, local, remote, deadline);
        let (application, service) = tokio::join!(application, service);
        application.unwrap();
        service.unwrap();
    })
    .await
    .expect("finite original legacy socket/transport fixture stalled");
}

/// Relays only actual envelopes through the existing bounded server bridge; offers get service delivery.
async fn service(
    mut peer: test_support::Peer,
    mut server: CallerServerSignalingDriver,
    local: u64,
    remote: &str,
    deadline: Instant,
) -> Result<(), Error> {
    let result = async {
        peer.send_text(&json!({"Type":2,"From":"Server","Message":json!({"ExpirationInSeconds":300,"TurnAuthServers":[]}).to_string()}).to_string()).await?;
        let mut server_open = true;
        loop {
            tokio::select! {
                request = server.recv(), if server_open => {
                    let Some(request) = request else { server_open = false; continue; };
                    peer.send_text(&json!({"Type":1,"From":remote,"Message":request.signal().to_string()}).to_string()).await?;
                    request.finish(Ok(SignalDelivery::ServiceAccepted));
                }
                frame = peer.recv_text() => {
                    let wire = match frame { Ok(Some(wire)) => wire, Ok(None) | Err(_) => break };
                    let frame: Value = serde_json::from_str(&wire).map_err(|_| Error::Signaling)?;
                    if frame["Type"] != 1 || frame["To"] != remote { return Err(Error::Signaling); }
                    let wire = frame["Message"].as_str().ok_or(Error::Signaling)?;
                    let message = Uuid::parse_str(frame["MessageId"].as_str().ok_or(Error::Signaling)?).map_err(|_| Error::Signaling)?;
                    let signal = nethernet_tokio::Signal::from_string(wire, local.to_string()).map_err(|_| Error::Signaling)?;
                    let admitted = server.prepare_delivery_before(&local.to_string(), wire, deadline).map_err(|_| Error::Signaling)?;
                    admitted.await.map_err(|_| Error::Signaling)?;
                    if signal.signal_type == SignalType::Offer {
                        peer.send_text(&json!({"Type":4,"MessageId":message,"Message":"{}"}).to_string()).await?;
                    }
                }
            }
        }
        Ok(())
    }.await;
    server.close();
    let _ = peer.close().await;
    result
}
