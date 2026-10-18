use super::*;
use bytes::Bytes;
use nethernet::identity::ServerIdentity;
use nethernet_tokio::signaling::http::{HttpServerConfig, HttpSignaling, HttpSignalingServer};
use nethernet_tokio::{ConnectionConfig, NetherServer};
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
                attempts: 1,
                ..Default::default()
            },
        );
        let (client, accepted) = tokio::join!(connecting, listener.accept());
        let mut client = client.unwrap();
        let mut accepted = accepted.unwrap();
        let owner = SessionRetirement::new(&client);
        let retained = owner.session();
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
        accepted.session.close().await.unwrap();
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
