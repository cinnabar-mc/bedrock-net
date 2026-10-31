//! The actual consumed accepting Login enters relay startup without a pack acknowledgment.

use super::*;

#[test]
fn packless_relay_preserves_login_flush_and_real_initialized_gates() {
    let (server, client, provider, now, utc) = ready_with_client();
    let deadline = server.deadline();
    let pending = server
        .relay_without_packs(
            ServerPackDelivery::default().max_metadata_bytes,
            &provider,
            now,
            utc,
        )
        .unwrap();
    assert_eq!(pending.deadline(), deadline);
    assert_eq!(pending.login().nonce(), "original-nonce");
    let success = on_wire(pending.packet().clone(), wire::Peer::Server);
    assert!(matches!(&success, packets::Packet::PlayStatus(status)
        if status.status == PlayStatusType::LoginSuccess));
    let LoginEvent::Send {
        login: client,
        packets,
    } = client.receive(success).unwrap()
    else {
        panic!("original LoginSuccess did not advance its actual client");
    };
    assert!(matches!(
        packets.as_slice(),
        [packets::Packet::ClientCacheStatus(_)]
    ));
    let ServerRelayProgress::Continue(relay) = pending.flushed(now).unwrap() else {
        panic!("LoginSuccess fabricated Initialized");
    };
    let LoginEvent::Startup { start_game } = client
        .receive(
            packets::StartGame {
                runtime_id: ActorRuntimeID(73),
                ..Default::default()
            }
            .into(),
        )
        .unwrap()
    else {
        panic!("packless Login invented a resource offer");
    };
    assert_eq!(start_game.runtime_id.0, 73);
    let relay = startup(relay, now);
    let pending = relay.forward_client(initialized(73), now).unwrap();
    assert_eq!(
        on_wire(pending.packet().clone(), wire::Peer::Client),
        initialized(73)
    );
    let ServerRelayProgress::Initialized(ready) = pending.flushed(now).unwrap() else {
        panic!("actual Initialized did not finish packless relay");
    };
    let accepted = ready.finish(&provider, now, utc).unwrap();
    assert_eq!(accepted.login().xuid(), "123");
    assert_eq!(accepted.login().nonce(), "original-nonce");
    assert_eq!(accepted.chunk_radius(), 5);
}

#[test]
fn packless_relay_preserves_original_provider_cutoff_and_premature_refusal() {
    let limit = ServerPackDelivery::default().max_metadata_bytes;
    let (server, _client, provider, now, utc) = ready_with_client();
    provider.revoked.set(true);
    let Err(error) = server.relay_without_packs(limit, &provider, now, utc) else {
        panic!("revoked Login acquired a packless continuation");
    };
    let (server, cause) = error.into_parts();
    assert!(matches!(cause, ServerSessionError::Handshake(_)));
    provider.revoked.set(false);
    assert!(
        server
            .relay_without_packs(limit, &provider, now, utc)
            .is_err()
    );

    let (server, _client, provider, now, utc) = ready_with_client();
    let deadline = server.deadline();
    let pending = server
        .relay_without_packs(limit, &provider, now, utc)
        .unwrap();
    let Err(error) = pending.flushed(deadline) else {
        panic!("LoginSuccess flush renewed the original cutoff");
    };
    let (pending, cause) = error.into_parts();
    assert!(matches!(cause, ServerSessionError::TimedOut));
    assert_eq!(pending.deadline(), deadline);
    assert!(pending.flushed(now).is_err());

    let (server, _client, provider, now, utc) = ready_with_client();
    let pending = server
        .relay_without_packs(limit, &provider, now, utc)
        .unwrap();
    let ServerRelayProgress::Continue(relay) = pending.flushed(now).unwrap() else {
        panic!("LoginSuccess fabricated initialization");
    };
    assert!(relay.forward_client(initialized(73), now).is_err());

    let (server, _client, provider, now, utc) = ready_with_client();
    let pending = server
        .relay_without_packs(limit, &provider, now, utc)
        .unwrap();
    let ServerRelayProgress::Continue(relay) = pending.flushed(now).unwrap() else {
        panic!("LoginSuccess fabricated initialization");
    };
    let pending = startup(relay, now)
        .forward_client(initialized(73), now)
        .unwrap();
    let ServerRelayProgress::Initialized(ready) = pending.flushed(now).unwrap() else {
        panic!("actual Initialized was lost");
    };
    provider.revoked.set(true);
    assert!(ready.finish(&provider, now, utc).is_err());
}
