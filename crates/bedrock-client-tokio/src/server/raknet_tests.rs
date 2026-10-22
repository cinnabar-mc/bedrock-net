// SPDX-License-Identifier: MIT

//! Real listener handoff, signed Login, encrypted FIFO and retained accepting sends.

use super::*;
use bedrock_client::{
    handshake::{ClientHandshake, HandshakeOptions, LoginEvent},
    server::{
        ServerAcknowledgmentEvent, ServerApprovalEvent, ServerLoginEvent, ServerSettingsEvent,
    },
};
use bedrock_net::login::{LoginError, LoginVerifier, TrustedIdentity};
use p384::ecdsa::VerifyingKey;
use raknet_tokio::prelude::{RakClient, RakServer, SendPermit, SessionSender};
use serde_json::value::RawValue;
use std::{
    future::poll_fn,
    net::UdpSocket,
    pin::pin,
    task::Poll,
    time::{Duration, SystemTime},
};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
const TIMEOUT: Duration = Duration::from_secs(10);
const CREDENTIAL: &str = "synthetic-provider-credential";

/// Explicit fixture trust still requires the actual signed client metadata proof.
struct Provider(VerifyingKey);
impl LoginVerifier for Provider {
    fn verify(&self, token: &str, _utc: SystemTime) -> Result<TrustedIdentity, LoginError> {
        if token != CREDENTIAL {
            return Err(LoginError::Authentication);
        }
        TrustedIdentity::new("123".into(), self.0)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn accepted_raknet_preserves_signed_handshake_cipher_fifo_and_canceled_send() {
    let reservation = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let mut listener = RakServer::new(address, |_| {}).start().await.unwrap();
    let endpoint = RakClient::new(|_| {}).start().await.unwrap();
    let (peer, accepted) = tokio::time::timeout(TIMEOUT, async {
        tokio::join!(endpoint.connect(address), listener.accept())
    })
    .await
    .expect("original RakNet listener handshake stalled");
    let accepted = accepted.unwrap();
    let sender = accepted.sender();
    let key = Arc::new(SigningKey::from_slice(&[4; 48]).unwrap());
    let provider = Provider(*key.verifying_key());
    let limits = BatchLimits::default();
    let deadline = now() + TIMEOUT;
    let (mut server, handshake) = AcceptingConnection::from_raknet(
        accepted,
        Arc::new(SigningKey::from_slice(&[5; 48]).unwrap()),
        ServerHandshakeOptions::default(),
        limits.max_decoded_bytes,
        deadline,
    )
    .unwrap();
    let mut peer = Connection::new(
        Transport::from_accepted_raknet(peer.unwrap()),
        limits,
        wire::Limits::receiving_from(wire::Peer::Server),
        limits.max_decoded_bytes,
    );
    let observed = tokio::time::timeout(TIMEOUT, async {
        let (serving, joining) = tokio::join!(
            serve(&mut server, handshake, &provider, deadline),
            join(&mut peer, key),
        );
        let identity = serving?;
        joining?;
        let canceled = canceled_send(&mut server, &mut peer, &sender, deadline).await?;
        Ok::<_, Box<dyn std::error::Error>>((identity, canceled))
    })
    .await;

    // The test verdict follows retirement of these same two original endpoint owners.
    let cleanup_deadline = now() + TIMEOUT;
    let settlement = server
        .begin_send_retirement(cleanup_deadline)
        .finish()
        .await;
    let mut retired = server.begin_close();
    drop(sender);
    let cleanup = tokio::time::timeout(TIMEOUT, async {
        let results = tokio::join!(
            retired.finish_close(cleanup_deadline),
            peer.transport_mut().finish_close(),
        );
        drop(retired);
        drop(peer);
        tokio::join!(listener.stop(), endpoint.stop());
        results
    })
    .await;
    let (server_closed, peer_closed) = cleanup.expect("original endpoint retirement stalled");
    assert!(
        server_closed.is_ok(),
        "server retirement: {server_closed:?}"
    );
    assert!(peer_closed.is_ok(), "peer retirement: {peer_closed:?}");
    assert!(
        settlement.is_ok(),
        "original send settlement: {settlement:?}"
    );
    let (identity, canceled) = observed.expect("paired Bedrock handshake stalled").unwrap();
    assert_eq!(identity, ("123".to_owned(), "original-nonce".to_owned()));
    assert!(
        canceled,
        "a full original command queue must withhold send admission"
    );
}

/// Drives only the existing consuming server states, with explicit fixture-owned approval.
async fn serve(
    server: &mut AcceptingConnection,
    handshake: ServerHandshake,
    provider: &Provider,
    deadline: Instant,
) -> TestResult<(String, String)> {
    let request = server.receive(deadline).await?;
    let ServerSettingsEvent::Settings(settings) =
        handshake.receive(request, provider, now(), utc())?
    else {
        return Err("missing actual settings request".into());
    };
    send(server, vec![settings.packet().clone().into()], deadline).await?;
    server.compression_flushed(settings.compression())?;
    let login = settings.flushed(now())?;
    let packet = server.receive(deadline).await?;
    let ServerLoginEvent::Verified(verified) = login.receive(packet, provider, now(), utc())?
    else {
        return Err("actual signed Login was not verified".into());
    };
    let approved = verified.authorize(|login| {
        if login.xuid() == "123" && login.nonce() == "original-nonce" {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fixture denied Login",
            ))
        }
    })?;
    let ServerApprovalEvent::KeyExchange(exchange) =
        approved.accept(provider, Some(&[7; 16]), now(), utc())?
    else {
        return Err("RakNet lost its required batch key exchange".into());
    };
    send(server, vec![exchange.packet().clone().into()], deadline).await?;
    let (acknowledgment, ciphers) = exchange.flushed(now())?;
    server.encryption_flushed(*ciphers)?;
    let packet = server.receive(deadline).await?;
    let ServerAcknowledgmentEvent::Ready(ready) =
        acknowledgment.receive(packet, provider, now(), utc())?
    else {
        return Err("original encrypted acknowledgment did not complete Login".into());
    };
    let accepted = ready.finish(provider, now(), utc())?;
    // This follows the acknowledgment in the same original encrypted batch.
    if !matches!(
        server.receive(deadline).await?,
        packets::Packet::ClientCacheStatus(_)
    ) {
        return Err("the acknowledgment transition lost its original FIFO sibling".into());
    }
    send(server, vec![time_packet(1), time_packet(2)], deadline).await?;
    Ok((
        accepted.login().xuid().to_owned(),
        accepted.login().nonce().to_owned(),
    ))
}

/// Uses the same generated client continuation and codec as ordinary client connections.
async fn join(peer: &mut Connection, key: Arc<SigningKey>) -> TestResult<()> {
    let client = ClientHandshake::new(key, HandshakeOptions::default())?;
    let (ready, _) = crate::handshake::settings(peer, client, &mut |_| {}).await?;
    let claims = RawValue::from_string(
        serde_json::json!({
            "Nonce": "original-nonce", "DeviceOS": 1,
            "GameVersion": bedrock_protocol::GAME_VERSION, "LanguageCode": "en_US",
            "SkinId": "synthetic", "ThirdPartyName": "Probe"
        })
        .to_string(),
    )?;
    let (client, packet) = ready.login_authenticated(CREDENTIAL, &claims)?;
    peer.send_packet(&packet.into(), wire::Peer::Client, 0, 0)
        .await?;
    let (_, packet) = peer.next_packet().await?;
    let LoginEvent::KeyExchange(exchange) = client.receive(packet)? else {
        return Err("client did not verify the actual server exchange".into());
    };
    let (_client, ciphers, response) = exchange.into_parts();
    let ciphers = ciphers.ok_or("client did not derive its batch ciphers")?;
    peer.enable_encryption(*ciphers)?;
    crate::handshake::send_packets(
        peer,
        &[
            response.into(),
            packets::ClientCacheStatus {
                is_cache_supported: false,
            }
            .into(),
        ],
        None,
        &mut |_| {},
    )
    .await?;
    expect_time(peer, 1).await?;
    expect_time(peer, 2).await
}

/// Cancels only borrowed progress and preserves the actual queue reservation and cipher cursor.
async fn canceled_send(
    server: &mut AcceptingConnection,
    peer: &mut Connection,
    sender: &SessionSender,
    deadline: Instant,
) -> TestResult<bool> {
    let mut held: Vec<SendPermit> = Vec::new();
    loop {
        let mut reservation = pin!(sender.reserve_send(0));
        match poll_fn(|cx| Poll::Ready(reservation.as_mut().poll(cx))).await {
            Poll::Ready(Ok(permit)) => held.push(permit),
            Poll::Ready(Err(error)) => return Err(error.into()),
            Poll::Pending => break,
        }
    }
    let pending = {
        let mut sending = server.prepare_packets(vec![time_packet(3)], deadline)?;
        let mut next = pin!(sending.next());
        poll_fn(|cx| Poll::Ready(next.as_mut().poll(cx).is_pending())).await
    };
    drop(held.pop());
    {
        let mut sending = server.resume_send()?;
        let _capacity = sending
            .next()
            .await?
            .ok_or("original send completed without capacity")?;
    }
    {
        let mut sending = server.resume_send()?;
        sending.reserved_capacity()?.commit()?;
    }
    {
        let mut sending = server.resume_send()?;
        if sending.next().await?.is_some() {
            return Err("original send duplicated its encoded message".into());
        }
        sending.finish()?;
    }
    drop(held);
    expect_time(peer, 3).await?;
    send(server, vec![time_packet(4)], deadline).await?;
    expect_time(peer, 4).await?;
    Ok(pending)
}

/// Finishes the exact original prepared effect before releasing its continuation.
async fn send(
    server: &mut AcceptingConnection,
    packets: Vec<packets::Packet>,
    deadline: Instant,
) -> io::Result<()> {
    let mut sending = server.prepare_packets(packets, deadline)?;
    while let Some(capacity) = sending.next().await? {
        capacity.commit()?;
    }
    sending.finish()
}

/// Uses a small generated server packet to observe the actual encrypted FIFO.
fn time_packet(time: i32) -> packets::Packet {
    packets::SetTime {
        time: wire::ZigZag32(time),
    }
    .into()
}

/// Checks decrypted generated data rather than transport scheduling or cipher internals.
async fn expect_time(peer: &mut Connection, expected: i32) -> TestResult<()> {
    match peer.next_packet().await?.1 {
        packets::Packet::SetTime(packet) if packet.time.0 == expected => Ok(()),
        _ => Err("encrypted packet order or cipher continuity changed".into()),
    }
}

/// Matches the real adapter's edge clock, including paused-clock controls.
fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// Keeps signature validation deterministic without acquiring an account or provider token.
fn utc() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1000)
}
