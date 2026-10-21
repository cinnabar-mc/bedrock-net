// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Real signed HTTP/DTLS/SCTP associations for integration fixtures; no account or world is created.

use super::AcceptingConnection;
use bedrock_client::server::ServerHandshakeOptions;
use nethernet::identity::{
    TokenVerifier,
    error::{IdentityError, Result as IdentityResult},
    jwt::{Claims, Jws},
};
use nethernet_tokio::{
    ClientIceConfig, ConnectionConfig, HttpServerConfig, HttpSignaling, HttpSignalingServer,
    NetherClient, NetherServer, SelfSignedIdentity, ServerIceConfig, ServerIdentity,
    SessionReceiver, SessionSender, TokenTrust,
};
use p384::{
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::Generate,
};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime},
};

pub(super) const TIMEOUT: Duration = Duration::from_secs(20);
const SERVER: &str = "synthetic-prepared-send-server";

/// Original signed association and all of its client, listener and signaling cleanup owners.
pub struct SignedPair {
    /// The same established accepting codec and send owner.
    pub wire: AcceptingConnection,
    /// Original server actor sender used to observe real queue capacity.
    pub sender: SessionSender,
    /// Original client association, including both receive queues.
    pub client: NetherClient,
    /// Original accepting listener; join it during fixture cleanup.
    pub listener: NetherServer,
    /// Original signed HTTP signaling server; shut it down during fixture cleanup.
    pub signaling: Arc<HttpSignalingServer>,
}

impl SignedPair {
    /// Retires and drains actual owners, then joins listener/HTTP tasks; no close token is used as join.
    pub async fn finish(self) -> bool {
        let Self {
            wire,
            sender,
            client,
            mut listener,
            signaling,
        } = self;
        let deadline = tokio::time::Instant::now().into_std() + TIMEOUT;
        let mut wire = wire.begin_close();
        let mut client = client.close();
        wire.finish_close(deadline).await.unwrap();
        let server_done = matches!(wire.receive_raw(deadline).await, Err(error) if error.kind() == io::ErrorKind::UnexpectedEof);
        let reliable = drain(&mut client.reliable).await;
        let unreliable = drain(&mut client.unreliable).await;
        drop(wire);
        drop(client);
        drop(sender);
        listener.close().await.unwrap();
        drop(listener);
        let joined = match Arc::try_unwrap(signaling) {
            Ok(signaling) => {
                signaling.shutdown().await;
                true
            }
            Err(signaling) => {
                drop(signaling);
                false
            }
        };
        server_done && reliable && unreliable && joined
    }
}

/// Retains the original handshake for real provider Login/startup controls on this association.
pub async fn signed_pair_with_key(
    client_key: Arc<SigningKey>,
    max_deferred_bytes: usize,
) -> (SignedPair, bedrock_client::server::ServerHandshake) {
    signed_pair_with_server_bind(
        client_key,
        (Ipv4Addr::LOCALHOST, 0).into(),
        max_deferred_bytes,
    )
    .await
}

/// Uses the same signed association with one caller-reserved server socket address.
pub(super) async fn signed_pair_with_server_bind(
    client_key: Arc<SigningKey>,
    server_bind: SocketAddr,
    max_deferred_bytes: usize,
) -> (SignedPair, bedrock_client::server::ServerHandshake) {
    let now = SystemTime::now();
    let key = Arc::new(SigningKey::generate());
    let signaling = Arc::new(
        HttpSignalingServer::bind(
            (Ipv4Addr::LOCALHOST, 0).into(),
            HttpServerConfig {
                network_id: SERVER.into(),
                signaler: nethernet::signaling::http::config::HttpSignalerConfig {
                    token_trust: Some(trust(*client_key.verifying_key(), None)),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap(),
    );
    let mut listener = NetherServer::bind_with(
        Arc::clone(&signaling),
        ConnectionConfig {
            identity: Some(Arc::new(
                ServerIdentity::from_key((*key).clone(), SERVER, now, Some(TIMEOUT)).unwrap(),
            )),
            server_ice: Some(ServerIceConfig {
                turn_streams: Vec::new(),
                turn_tls: None,
                ice: Default::default(),
                bind_addr: server_bind,
            }),
            attempts: 1,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let client = NetherClient::connect_with(
        HttpSignaling::new("synthetic-prepared-send-client".into()).unwrap(),
        format!("http://{}", signaling.local_addr()),
        ConnectionConfig {
            identity: Some(Arc::new(
                SelfSignedIdentity::from_key(client_key, now, TIMEOUT).unwrap(),
            )),
            server_trust: Some(trust(*key.verifying_key(), Some(SERVER))),
            client_ice: Some(ClientIceConfig {
                turn_streams: Vec::new(),
                turn_tls: None,
                ice: Default::default(),
                bind_addr: Some((Ipv4Addr::LOCALHOST, 0).into()),
            }),
            attempts: 1,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let accepted = listener.accept().await.unwrap();
    let sender = accepted.session.sender();
    let (wire, handshake) = AcceptingConnection::from_nether(
        accepted,
        key,
        ServerHandshakeOptions::default(),
        max_deferred_bytes,
        tokio::time::Instant::now().into_std() + TIMEOUT,
    )
    .await
    .unwrap();
    (
        SignedPair {
            wire,
            sender,
            client,
            listener,
            signaling,
        },
        handshake,
    )
}

struct ExpectedToken {
    key: VerifyingKey,
    issuer: Option<&'static str>,
}

impl TokenVerifier for ExpectedToken {
    fn verify(&self, token: &str, now: SystemTime) -> IdentityResult<Claims> {
        let token = Jws::parse(token)?;
        if token.header.alg != "ES384" {
            return Err(IdentityError::Untrusted(
                "unexpected fixture algorithm".into(),
            ));
        }
        token.verify_es384(&self.key)?;
        let claims = token.claims()?;
        claims.check_expiry(now)?;
        if claims.client_public_key()? != self.key
            || claims.issuer() != self.issuer
            || !claims.audience().is_empty()
        {
            return Err(IdentityError::Untrusted(
                "unexpected fixture identity".into(),
            ));
        }
        Ok(claims)
    }
}

/// Trusts the original local proof key and fixture issuer, without a production policy fallback.
fn trust(key: VerifyingKey, issuer: Option<&'static str>) -> TokenTrust {
    TokenTrust::Provider(Arc::new(ExpectedToken { key, issuer }))
}

/// Drains original receive queues through their terminal and records unexpected receive errors.
pub(super) async fn drain(receiver: &mut SessionReceiver) -> bool {
    let mut orderly = true;
    loop {
        match receiver.recv().await {
            Ok(Some(_)) => {}
            Ok(None) => return orderly,
            Err(_) => orderly = false,
        }
    }
}
