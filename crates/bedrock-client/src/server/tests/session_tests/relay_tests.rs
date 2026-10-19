//! Real generated Login/packs followed by actual upstream controls, without an authored world.

use super::*;
use bedrock_protocol::enums::PlayStatusType;
use std::time::Duration;

/// Uses the original provider/approval/pack fixture to obtain the real public relay boundary.
fn prepared_relay() -> (ServerRelaying<Grant>, Provider, Instant, SystemTime) {
    let (server, packets, client, provider, now, utc) = accepted(snapshot());
    let (server, _, _) = exchange_packs(server, packets, client, now);
    let relay = server.relay_world(&provider, now, utc).unwrap();
    (relay, provider, now, utc)
}

/// Frames and decodes the actual retained effect before acknowledging the adapter's forward.
fn forward(
    relay: ServerRelaying<Grant>,
    packet: packets::Packet,
    source: wire::Peer,
    now: Instant,
) -> ServerRelaying<Grant> {
    let pending = match source {
        wire::Peer::Server => relay.forward_server(packet, now),
        wire::Peer::Client => relay.forward_client(packet, now),
    }
    .unwrap();
    let forwarded = on_wire(pending.packet().clone(), source);
    assert_eq!(&forwarded, pending.packet());
    assert_eq!(pending.login().xuid(), "123");
    match pending.flushed(now).unwrap() {
        ServerRelayProgress::Continue(relay) => relay,
        ServerRelayProgress::Initialized(_) => panic!("startup control fabricated initialization"),
    }
}

/// Retains original early PlayerSpawn ordering and never generates a replacement radius response.
fn startup(mut relay: ServerRelaying<Grant>, now: Instant) -> ServerRelaying<Grant> {
    for packet in [
        packets::PlayStatus {
            status: PlayStatusType::Playerspawn,
        }
        .into(),
        packets::Packet::StartGame(Box::new(packets::StartGame {
            runtime_id: ActorRuntimeID(73),
            ..Default::default()
        })),
        packets::ItemRegistry::default().into(),
    ] {
        relay = forward(relay, packet, wire::Peer::Server, now);
    }
    relay = forward(relay, radius().into(), wire::Peer::Client, now);
    forward(
        relay,
        packets::ChunkRadiusUpdated {
            chunk_radius: wire::ZigZag32(5),
        }
        .into(),
        wire::Peer::Server,
        now,
    )
}

/// The wire acknowledgment is always obtained from a generated client packet.
fn initialized(id: u64) -> packets::Packet {
    on_wire(
        packets::SetLocalPlayerAsInitialized {
            player_id: ActorRuntimeID(id),
        }
        .into(),
        wire::Peer::Client,
    )
}

#[test]
fn relayed_world_requires_original_control_flushes_and_matching_initialized() {
    let (relay, provider, now, utc) = prepared_relay();
    let deadline = relay.deadline();
    let relay = startup(relay, now);
    let pending = relay.forward_client(initialized(73), now).unwrap();
    assert_eq!(pending.deadline(), deadline);
    assert_eq!(pending.login().nonce(), "original-nonce");
    // No Initialized capability exists while the actual upstream forward is still pending.
    let forwarded = on_wire(pending.packet().clone(), wire::Peer::Client);
    assert_eq!(forwarded, initialized(73));
    let ServerRelayProgress::Initialized(ready) = pending.flushed(now).unwrap() else {
        panic!("actual original Initialized did not advance the relay");
    };
    assert_eq!(ready.deadline(), deadline);
    let accepted = ready.finish(&provider, now, utc).unwrap();
    assert_eq!(accepted.login().xuid(), "123");
    assert_eq!(accepted.login().nonce(), "original-nonce");
    assert_eq!(accepted.chunk_radius(), 5);
    assert!(!accepted.client_cache_enabled());
}

#[test]
fn relayed_invalid_or_premature_initialization_seals_the_same_owner() {
    for premature in [true, false] {
        let (relay, _provider, now, _) = prepared_relay();
        let relay = if premature {
            relay
        } else {
            startup(relay, now)
        };
        let id = if premature { 73 } else { 74 };
        let Err(error) = relay.forward_client(initialized(id), now) else {
            panic!("unverified initialization acquired a forwarding capability");
        };
        let (relay, cause) = error.into_parts();
        assert!(matches!(cause, ServerSessionError::InvalidData(_)));
        assert_eq!(relay.login().nonce(), "original-nonce");
        let Err(error) = relay.forward_server(packets::ItemRegistry::default().into(), now) else {
            panic!("failed original relay reopened admission");
        };
        assert!(matches!(
            error.into_parts().1,
            ServerSessionError::InvalidState
        ));
    }
}

#[test]
fn relayed_original_deadline_and_provider_survive_all_forward_boundaries() {
    let (relay, _provider, now, _) = prepared_relay();
    let deadline = relay.deadline();
    let pending = relay
        .forward_server(packets::ItemRegistry::default().into(), now)
        .unwrap();
    let Err(error) = pending.flushed(deadline) else {
        panic!("pending relay forward renewed its original deadline");
    };
    let (pending, cause) = error.into_parts();
    assert!(matches!(cause, ServerSessionError::TimedOut));
    assert_eq!(pending.deadline(), deadline);
    assert!(pending.flushed(deadline - Duration::from_nanos(1)).is_err());

    let (relay, provider, now, utc) = prepared_relay();
    let relay = startup(relay, now);
    let pending = relay.forward_client(initialized(73), now).unwrap();
    let ServerRelayProgress::Initialized(ready) = pending.flushed(now).unwrap() else {
        panic!("matching initialization missing");
    };
    provider.revoked.set(true);
    let Err(error) = ready.finish(&provider, now, utc) else {
        panic!("revoked original provider initialized a relayed session");
    };
    let (ready, cause) = error.into_parts();
    assert!(matches!(
        cause,
        ServerSessionError::Login(LoginError::Authentication)
    ));
    provider.revoked.set(false);
    assert!(ready.finish(&provider, now, utc).is_err());
}

#[test]
fn relayed_bad_radius_and_conflicting_runtime_identity_cannot_advance() {
    let (relay, _, now, _) = prepared_relay();
    let Err(error) = relay.forward_server(
        packets::ChunkRadiusUpdated {
            chunk_radius: wire::ZigZag32(0),
        }
        .into(),
        now,
    ) else {
        panic!("invalid actual radius acquired a forwarding continuation");
    };
    assert!(matches!(
        error.into_parts().1,
        ServerSessionError::InvalidData(_)
    ));

    let (relay, _, now, _) = prepared_relay();
    let relay = startup(relay, now);
    let Err(error) = relay.forward_server(
        packets::Packet::StartGame(Box::new(packets::StartGame {
            runtime_id: ActorRuntimeID(74),
            ..Default::default()
        })),
        now,
    ) else {
        panic!("upstream replaced the original relayed runtime identity");
    };
    assert!(matches!(
        error.into_parts().1,
        ServerSessionError::InvalidData(_)
    ));
}
