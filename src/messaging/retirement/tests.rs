use super::*;
use bytes::Bytes;
use nethernet::identity::ServerIdentity;
use nethernet_tokio::signaling::http::{HttpServerConfig, HttpSignaling, HttpSignalingServer};
use nethernet_tokio::{ClientIceConfig, ConnectionConfig, NetherServer, ServerIceConfig};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

/// The actual ready-transport guard must retire retained handles when its messaging lifetime ends.
#[tokio::test]
async fn dropping_messaging_transport_owner_closes_a_retained_session() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let signaling = HttpSignalingServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            HttpServerConfig {
                network_id: "2".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let target = format!("http://{}", signaling.local_addr());
        let mut listener = NetherServer::bind_with(
            signaling,
            ConnectionConfig {
                identity: Some(Arc::new(
                    ServerIdentity::generate("synthetic-server", SystemTime::now()).unwrap(),
                )),
                // Keep this lifetime test independent of the host's default network route.
                server_ice: Some(ServerIceConfig {
                    bind_addr: "127.0.0.1:0".parse().unwrap(),
                    ice: Default::default(),
                    turn_streams: Vec::new(),
                    turn_tls: None,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let connecting = NetherClient::connect_with(
            HttpSignaling::new("1".into()).unwrap(),
            target,
            ConnectionConfig {
                identity: Some(Arc::new(
                    ServerIdentity::generate("synthetic-client", SystemTime::now()).unwrap(),
                )),
                client_ice: Some(ClientIceConfig {
                    bind_addr: Some("127.0.0.1:0".parse().unwrap()),
                    ice: Default::default(),
                    turn_streams: Vec::new(),
                    turn_tls: None,
                }),
                attempts: 1,
                ..Default::default()
            },
        );
        let (client, accepted) = tokio::join!(connecting, listener.accept());
        let mut client = client.unwrap();
        let mut accepted = accepted.unwrap();
        let owner = SessionRetirement::new(&client);
        let retained = owner.sender();
        retained
            .send(Bytes::from_static(b"live retained handle"))
            .await
            .unwrap();
        assert_eq!(
            accepted.reliable.recv().await.unwrap().unwrap(),
            "live retained handle"
        );
        accepted
            .session
            .send(Bytes::from_static(b"live reverse channel"))
            .await
            .unwrap();
        assert_eq!(
            client.recv().await.unwrap().unwrap(),
            "live reverse channel"
        );
        drop(client);
        drop(owner);
        let closed = retained.is_closed().await;
        let late = retained
            .send(Bytes::from_static(b"must not outlive messaging"))
            .await;
        // Always clean up the real actors before an intended fail-first assertion.
        retained.close().await.unwrap();
        let mut retired = accepted.close();
        while retired.reliable.recv().await.unwrap().is_some() {}
        while retired.unreliable.recv().await.unwrap().is_some() {}
        listener.close().await.unwrap();
        assert!(
            closed,
            "messaging owner drop left its retained transport session live"
        );
        assert!(
            late.is_err(),
            "a retained Session admitted data after messaging owner retirement"
        );
    })
    .await
    .expect("actual transport lifetime witness failed to complete");
}
