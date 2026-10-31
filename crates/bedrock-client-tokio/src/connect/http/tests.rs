//! Selected HTTP endpoint, signed Login, and failure invalidation on actual transport owners.

use super::*;
use crate::{PacketIo, connection::Connection, handshake, transport::Transport};
use bedrock_client::handshake::{ClientHandshake, HandshakeOptions};
use bedrock_net::BatchLimits;
use bedrock_protocol::{packets, wire};
use nethernet_tokio::{
    ClientIceConfig, HttpServerConfig, HttpSignalingServer, NetherServer, SelfSignedIdentity,
    ServerIceConfig, ServerIdentity, TokenTrust,
    signaling::http::probe::{HttpProbe, ProbeCache},
};
use p384::{ecdsa::SigningKey, elliptic_curve::Generate};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// Successful Login keeps its choice; refusal and dropped Login waits forget that exact choice.
#[tokio::test]
async fn addressed_login_uses_the_selected_url_and_invalidates_failed_attempts() {
    for outcome in 0..4 {
        tokio::time::timeout(Duration::from_secs(20), attempt(outcome))
            .await
            .unwrap();
    }
}

/// Runs discovery through a finite proxy so a scheme-default endpoint needs no privileged port.
async fn attempt(outcome: usize) {
    let now = SystemTime::now();
    let key = Arc::new(SigningKey::generate());
    let server_key = Arc::new(SigningKey::generate());
    let signaling = Arc::new(
        HttpSignalingServer::bind("127.0.0.1:0".parse().unwrap(), HttpServerConfig::default())
            .await
            .unwrap(),
    );
    let mut listener = NetherServer::bind_with(
        Arc::clone(&signaling),
        ConnectionConfig {
            identity: Some(Arc::new(
                ServerIdentity::from_key(
                    (*server_key).clone(),
                    "fixture",
                    now,
                    Some(Duration::from_secs(60)),
                )
                .unwrap(),
            )),
            token_trust: Some(TokenTrust::Any),
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
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let secure = Arc::new(AtomicUsize::new(0));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let proxy_address = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(serve_proxy(
        proxy,
        signaling.local_addr(),
        Arc::clone(&secure),
        stopped,
    ));
    let probe = HttpProbe::new(
        reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{proxy_address}")).unwrap()),
    )
    .unwrap();
    let cache = ProbeCache::default();
    let dialer = HttpDialer::new(probe.clone(), "guest".into()).with_cache(cache.clone());
    let config = ConnectionConfig {
        identity: Some(Arc::new(
            SelfSignedIdentity::from_key(Arc::clone(&key), now, Duration::from_secs(60))
                .unwrap()
                .with_domain("authorization.fixture"),
        )),
        server_trust: Some(TokenTrust::Any),
        client_ice: Some(ClientIceConfig {
            bind_addr: Some("127.0.0.1:0".parse().unwrap()),
            ice: Default::default(),
            turn_streams: Vec::new(),
            turn_tls: None,
        }),
        attempts: 1,
        ..Default::default()
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let (connected, accepted) = {
        let connecting = dialer.connect("joined.fixture", 0, config, deadline, None);
        let accepting = listener.accept();
        tokio::pin!(connecting, accepting);
        tokio::select! {
            result = &mut connecting => {
                let connected = result.unwrap_or_else(|error| panic!("HTTP setup refused: {}", error.get_ref().unwrap().source().unwrap()));
                (connected, accepting.await.unwrap())
            },
            result = &mut accepting => (connecting.await.unwrap(), result.unwrap()),
        }
    };
    assert_eq!(connected.login_address(), "http://joined.fixture:80");
    let peer_key = accepted
        .session
        .player()
        .await
        .unwrap()
        .client_public_key()
        .unwrap();
    assert_eq!(peer_key, *key.verifying_key());
    let limits = BatchLimits::default();
    let mut client = Connection::new(
        connected.into_transport(),
        limits,
        wire::Limits::receiving_from(wire::Peer::Server),
        65536,
    );
    let mut server = Connection::new(
        Transport::from_accepted(accepted),
        limits,
        wire::Limits::receiving_from(wire::Peer::Client),
        65536,
    );
    let configured = ClientHandshake::new(Arc::clone(&key), HandshakeOptions::default()).unwrap();
    let server_handshake = bedrock_client::server::ServerHandshake::new_offline(
        server_key,
        Some(peer_key),
        Default::default(),
        deadline.into_std(),
        std::time::Instant::now(),
    )
    .unwrap();
    let (received, receiving) = tokio::sync::oneshot::channel();
    let (complete, completed) = tokio::sync::oneshot::channel();
    let application = async {
        if outcome == 3 {
            let mut observe = |_: handshake::Observation<'_>| {};
            let settings = handshake::settings(&mut client, configured, &mut observe);
            tokio::pin!(settings);
            tokio::select! { biased;
                _ = receiving => {},
                result = &mut settings => panic!("settings completed before cancellation: {}", result.is_ok()),
            }
        } else {
            let (ready, _) = handshake::settings(&mut client, configured, &mut |_| {})
                .await
                .unwrap();
            let claims = serde_json::value::RawValue::from_string(r#"{"DeviceOS":1,"GameVersion":"1.26.60","LanguageCode":"en_US","SkinId":"synthetic","ThirdPartyName":"Probe","serveraddress":"wrong.fixture:19132","Opaque":1e+000}"#.into()).unwrap();
            let mut observe = |_: handshake::Observation<'_>| {};
            let login = handshake::login(
                &mut client,
                ready,
                handshake::LoginData::Offline {
                    identity: bedrock_net::login::OfflineIdentity {
                        display_name: "Probe",
                        identity: "00000000-0000-4000-8000-000000000001",
                        xuid: "",
                        playfab_id: "",
                        playfab_title_id: "",
                    },
                    claims: &claims,
                    now,
                },
                &mut observe,
            );
            {
                tokio::pin!(login);
                if outcome == 2 {
                    tokio::select! { biased;
                        _ = receiving => {},
                        result = &mut login => panic!("Login completed before cancellation: {}", result.is_ok()),
                    }
                } else {
                    assert_eq!(login.await.is_ok(), outcome == 0);
                }
            }
        }
        complete.send(()).unwrap();
        client.close().await.unwrap();
        client.finish_close().await.unwrap();
    };
    let accepting = async {
        use bedrock_client::server::{OfflinePolicy, ServerLoginEvent, ServerSettingsEvent};
        let policy = OfflinePolicy::new(|_: &str| Ok(()));
        let request = server.next_packet().await.unwrap().1;
        let ServerSettingsEvent::Settings(pending) = server_handshake
            .receive(request, &policy, std::time::Instant::now(), now)
            .unwrap()
        else {
            panic!("settings missing")
        };
        if outcome == 3 {
            received.send(()).unwrap();
        } else {
            let settings = pending.packet().clone();
            let compression = pending.compression();
            server
                .send_packet(&settings.into(), wire::Peer::Server, 0, 0)
                .await
                .unwrap();
            server.enable_compression(compression).unwrap();
            let login = pending.flushed(std::time::Instant::now()).ok().unwrap();
            let packet = server.next_packet().await.unwrap().1;
            let ServerLoginEvent::Verified(verified) = login
                .receive(packet, &policy, std::time::Instant::now(), now)
                .unwrap()
            else {
                panic!("Login missing")
            };
            let metadata = verified.login().client_data();
            let value: serde_json::Value = serde_json::from_str(metadata.get()).unwrap();
            assert_eq!(value["ServerAddress"], "http://joined.fixture:80");
            assert!(metadata.get().contains("1e+000"));
            if outcome == 2 {
                received.send(()).unwrap();
            } else {
                let response = if outcome == 0 {
                    packets::Packet::ResourcePacksInfo(Default::default())
                } else {
                    packets::Packet::Disconnect(Default::default())
                };
                server
                    .send_packet(&response, wire::Peer::Server, 0, 0)
                    .await
                    .unwrap();
            }
        }
        completed.await.unwrap();
        server.close().await.unwrap();
        server.finish_close().await.unwrap();
    };
    tokio::join!(application, accepting);
    let before = secure.load(Ordering::SeqCst);
    assert_eq!(before, 2);
    let selected = probe
        .select("joined.fixture", 0, Some(&cache), deadline)
        .await
        .unwrap();
    assert_eq!(selected.login_address(), "http://joined.fixture:80");
    assert_eq!(
        secure.load(Ordering::SeqCst) - before,
        if outcome == 0 { 0 } else { 2 }
    );
    stop.send(()).unwrap();
    proxy_task.await.unwrap();
    listener.close().await.unwrap();
}

/// Serves proxy requests concurrently, then joins only this fixture's owned requests.
async fn serve_proxy(
    listener: TcpListener,
    upstream: std::net::SocketAddr,
    secure: Arc<AtomicUsize>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) {
    let mut requests = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut stop => break,
            socket = listener.accept() => {
                let (socket, _) = socket.unwrap();
                requests.spawn(proxy_request(socket, upstream, Arc::clone(&secure)));
            }
            result = requests.join_next(), if !requests.is_empty() => { result.unwrap().unwrap(); }
        }
    }
    requests.shutdown().await;
}

/// Rejects HTTPS and game-port HTTP, forwarding only the chosen default-port HTTP offer.
async fn proxy_request(
    mut socket: tokio::net::TcpStream,
    upstream: std::net::SocketAddr,
    secure: Arc<AtomicUsize>,
) {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        request.push(socket.read_u8().await.unwrap());
        assert!(request.len() < 16384);
    }
    let headers = String::from_utf8(request).unwrap();
    let mut line = headers.lines().next().unwrap().split_whitespace();
    let method = line.next().unwrap();
    let url = line.next().unwrap();
    let (status, body) = if method == "CONNECT" {
        secure.fetch_add(1, Ordering::SeqCst);
        (502, Vec::new())
    } else if method == "GET" {
        (if url.contains(":19132/") { 404 } else { 200 }, Vec::new())
    } else {
        assert_eq!(method, "POST");
        let length: usize = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .unwrap();
        let mut body = vec![0; length];
        socket.read_exact(&mut body).await.unwrap();
        let path = url.strip_prefix("http://joined.fixture").unwrap();
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(format!("http://{upstream}{path}"))
            .header("content-type", "application/sdp")
            .body(body)
            .send()
            .await
            .unwrap();
        (
            response.status().as_u16(),
            response.bytes().await.unwrap().to_vec(),
        )
    };
    socket
        .write_all(
            format!(
                "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    socket.write_all(&body).await.unwrap();
}
