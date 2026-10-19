//! Actual SDK TURN acquisition hands unopened service targets to the same existing client configuration.

use crate::messaging::acquire_ice;
use bedrock_services::signaling::websocket::{SocketError, test_support};
use nethernet::session::{IceConfig, IcePolicy, IceServer, TurnAddressFamily, TurnStreamSecurity};
use nethernet_tokio::{ClientIceConfig, ConnectionConfig};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

/// The original service request/receipt supplies both carrier sets without replacing configured policy or bind.
#[tokio::test]
async fn actual_turn_acquisition_retains_full_service_targets_and_original_policy() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (mut socket, mut peer) = test_support::pair(7).await;
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let gather_timeout = Duration::from_secs(2);
        let config = ConnectionConfig {
            client_ice: Some(ClientIceConfig {
                ice: IceConfig {
                    gather_timeout,
                    policy: IcePolicy::RelayOnly,
                    ..Default::default()
                },
                bind_addr: Some(bind),
                turn_streams: Vec::new(),
                turn_tls: None,
            }),
            ..Default::default()
        };
        let application = acquire_ice(&mut socket, &config, Instant::now() + Duration::from_secs(10));
        let service = async {
            let wire = peer.recv_text().await.unwrap().unwrap();
            let request: Value = serde_json::from_str(&wire).unwrap();
            let observed_id = request["id"].is_u64();
            let sent = peer.send_text(&json!({"jsonrpc":"2.0","id":request["id"],"result":{
                "ExpirationInSeconds":300,"TurnAuthServers":[{
                    "Username":"original-user","Password":"original-password","Urls":[
                        "turn:127.0.0.1:3478?transport=udp",
                        "turn:127.0.0.1:3478?transport=tcp",
                        "turns:127.0.0.1:5349",
                        "turn:[::1]:3478?transport=tcp"
                    ]
                }]
            }}).to_string()).await;
            (observed_id, sent)
        };
        let (resolved, (observed_id, sent)) = tokio::join!(application, service);
        let original_expiry = socket.credentials().map(|credentials| credentials.expires_at());
        socket.close();
        let closed = async { socket.drive().await };
        let peer_closed = async {
            let terminal = peer.recv_text().await;
            let closed = peer.close().await;
            (terminal, closed)
        };
        let (closed, (terminal, peer_closed)) = tokio::join!(closed, peer_closed);
        drop((socket, peer));

        assert!(observed_id);
        sent.expect("original service credential response");
        assert!(matches!(closed, Err(SocketError::Closed)));
        assert!(matches!(terminal, Ok(None)));
        peer_closed.expect("original fixture service socket retirement");
        let resolved = resolved.expect("original correlated TURN acquisition");
        let original_expiry = original_expiry.expect("actual original SDK credential receipt");
        assert_eq!(resolved.bind_addr, Some(bind));
        assert_eq!(resolved.ice.gather_timeout, gather_timeout);
        assert_eq!(resolved.ice.policy, IcePolicy::RelayOnly);
        assert!(resolved.turn_tls.is_none());
        assert!(matches!(resolved.ice.servers.as_slice(), [IceServer::TurnWithFamily { family: TurnAddressFamily::Ipv4, .. }]));
        assert_eq!(resolved.turn_streams.len(), 3);
        assert!(resolved.turn_streams.iter().any(|target| target.remote.is_ipv6() && target.security == TurnStreamSecurity::Tcp));
        assert!(resolved.turn_streams.iter().any(|target| matches!(&target.security, TurnStreamSecurity::Tls { server_name } if server_name == "127.0.0.1")));
        for target in &resolved.turn_streams {
            assert!(target.bind_ip.is_none() && target.requested_family.is_none());
            assert_eq!(target.admission_deadline(original_expiry + Duration::from_secs(1)), original_expiry);
        }
    })
    .await
    .expect("finite original SDK TURN acquisition fixture stalled");
}
