use super::*;
use bedrock_protocol::{
    types::{ActorRuntimeID, ItemData},
    wire,
};

const RUNTIME_ID: u64 = 42;

/// Supplies application-selected distances directly, without a renderer dependency.
fn negotiation() -> SpawnNegotiation {
    SpawnNegotiation::new(packets::RequestChunkRadius {
        chunk_radius: wire::ZigZag32(12),
        max_chunk_radius: wire::U8(16),
    })
    .unwrap()
}

/// Carries only the local runtime identity needed by the startup state machine.
fn start(runtime_id: u64) -> packets::Packet {
    packets::Packet::StartGame(Box::new(packets::StartGame {
        runtime_id: ActorRuntimeID(runtime_id),
        ..Default::default()
    }))
}

/// Distinguishes the first item registry from a later empty/custom-only table.
fn registry(name: &str) -> packets::Packet {
    packets::Packet::ItemRegistry(packets::ItemRegistry {
        item_data: vec![ItemData {
            item_name: name.into(),
            ..Default::default()
        }],
    })
}

/// Represents a server-approved initial view distance.
fn radius(value: i32) -> packets::Packet {
    packets::Packet::ChunkRadiusUpdated(packets::ChunkRadiusUpdated {
        chunk_radius: wire::ZigZag32(value),
    })
}

/// Completes the server's spawn indication independently of the radius response.
fn player_spawn() -> packets::Packet {
    packets::Packet::PlayStatus(packets::PlayStatus {
        status: PlayStatusType::Playerspawn,
    })
}

#[test]
fn first_startup_definitions_prepare_early_and_radius_is_requested_once() {
    let mut client = negotiation();
    assert!(client.receive(registry("first")).unwrap().startup.is_none());
    assert!(client.receive(registry("later")).unwrap().startup.is_none());
    let update = client.receive(start(RUNTIME_ID)).unwrap();
    assert_eq!(update.request_radius.unwrap().chunk_radius.0, 12);
    let startup = update.startup.unwrap();
    assert_eq!(
        startup.item_registry.item_data[0]
            .item_name
            .to_str()
            .unwrap(),
        "first"
    );
    assert!(update.ready.is_none());
    assert!(
        client
            .receive(start(RUNTIME_ID))
            .unwrap()
            .request_radius
            .is_none()
    );
    assert!(client.receive(player_spawn()).unwrap().ready.is_none());
    let update = client.receive(radius(8)).unwrap();
    let ready = update.ready.unwrap();
    assert_eq!(ready.runtime_id(), RUNTIME_ID);
    assert!(!ready.terrain_received());
    assert!(matches!(
        *update.deferred.unwrap(),
        packets::Packet::ChunkRadiusUpdated(_)
    ));
    assert_eq!(ready.finish_loading().player_id.0, RUNTIME_ID);
}

#[test]
fn deferred_input_keeps_fifo_order_and_terrain_fact_until_ready() {
    let mut client = negotiation();
    client.receive(start(RUNTIME_ID)).unwrap();
    // Raw callers retain chunk bytes and only supply the ID until ordinary play decoding.
    client
        .receive_deferred(packets::PacketId::LevelChunk)
        .unwrap();
    let mut deferred = Vec::new();
    let inputs = [
        packets::Packet::SetTime(packets::SetTime {
            time: wire::ZigZag32(1),
        }),
        radius(8),
        packets::Packet::SetTime(packets::SetTime {
            time: wire::ZigZag32(2),
        }),
    ];
    for packet in inputs.clone() {
        let update = client.receive(packet).unwrap();
        deferred.push(*update.deferred.unwrap());
        assert!(update.ready.is_none());
    }
    assert_eq!(deferred, inputs);
    client.receive(player_spawn()).unwrap();
    let update = client.receive(registry("first")).unwrap();
    assert!(update.startup.is_some());
    assert!(update.ready.unwrap().terrain_received());
}

#[test]
fn malformed_prerequisites_fail_before_initialization() {
    let mut client = negotiation();
    client.receive(start(RUNTIME_ID)).unwrap();
    assert!(
        matches!(client.receive(start(RUNTIME_ID + 1)), Err(SpawnError::ConflictingRuntimeId { first: RUNTIME_ID, received }) if received == RUNTIME_ID + 1)
    );
    let mut client = negotiation();
    assert!(matches!(
        client.receive(radius(0)),
        Err(SpawnError::InvalidRadius(0))
    ));
    assert!(matches!(
        client.receive(start(RUNTIME_ID)),
        Err(SpawnError::InvalidState)
    ));
}

/// Startup returns every non-spawn status intact so its caller can retain terminal meaning.
#[test]
fn startup_returns_non_spawn_play_status_without_claiming_readiness() {
    let mut client = negotiation();
    client.receive(start(RUNTIME_ID)).unwrap();
    client.receive(registry("first")).unwrap();
    client.receive(radius(8)).unwrap();
    for status in [
        PlayStatusType::LoginfailedServerfullsubclient,
        PlayStatusType::Loginsuccess,
        PlayStatusType::Unknown(999),
    ] {
        let packet = packets::Packet::PlayStatus(packets::PlayStatus { status });
        let update = client.receive(packet.clone()).unwrap();
        assert!(update.ready.is_none());
        assert!(update.startup.is_none());
        assert_eq!(
            update.deferred.as_deref(),
            Some(&packet),
            "startup consumed a non-spawn status instead of preserving it for the caller"
        );
    }
    let ready = client.receive(player_spawn()).unwrap().ready.unwrap();
    assert_eq!(ready.finish_loading().player_id.0, RUNTIME_ID);
}

/// All original startup facts remain required, but a server's radius reply may arrive in play.
#[test]
fn startup_ready_does_not_require_a_radius_reply_in_any_fact_order() {
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let mut client = negotiation();
        client
            .receive_deferred(packets::PacketId::LevelChunk)
            .unwrap();
        let mut requests = 0;
        let mut definitions = 0;
        let mut ready = None;
        for (position, fact) in order.into_iter().enumerate() {
            let packet = match fact {
                0 => start(RUNTIME_ID),
                1 => registry("first"),
                2 => player_spawn(),
                _ => unreachable!("the three original startup facts"),
            };
            let update = client.receive(packet).unwrap();
            if let Some(request) = update.request_radius {
                requests += 1;
                assert_eq!(request.chunk_radius.0, 12);
                assert_eq!(request.max_chunk_radius.0, 16);
            }
            if let Some(startup) = update.startup {
                definitions += 1;
                assert_eq!(startup.start_game.runtime_id.0, RUNTIME_ID);
                assert_eq!(
                    startup.item_registry.item_data[0]
                        .item_name
                        .to_str()
                        .unwrap(),
                    "first"
                );
            }
            assert!(update.deferred.is_none());
            if position < 2 {
                assert!(
                    update.ready.is_none(),
                    "missing startup fact in order {order:?}"
                );
            }
            ready = update.ready.or(ready);
        }
        assert_eq!(requests, 1);
        assert_eq!(definitions, 1);
        let ready =
            ready.expect("all real startup facts must complete while the radius reply is withheld");
        assert_eq!(ready.runtime_id(), RUNTIME_ID);
        assert!(ready.terrain_received());
        assert_eq!(ready.finish_loading().player_id.0, RUNTIME_ID);
    }
}
