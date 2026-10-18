use bedrock_client::{
    handshake::{ClientHandshake, HandshakeEvent, HandshakeOptions},
    packs::PackEvent,
    spawn::{SpawnNegotiation, SpawnReady},
};
use bedrock_net::login::OfflineIdentity;
use bedrock_protocol::{enums::PlayStatusType, packets, types::ActorRuntimeID, wire};
use p384::ecdsa::SigningKey;
use serde_json::value::RawValue;
use std::time::SystemTime;

#[test]
fn early_player_spawn_survives_pack_and_handshake_owners_until_startup() {
    let mut handshake = ClientHandshake::new(
        SigningKey::from_slice(&[1; 48]).unwrap(),
        HandshakeOptions {
            blob_cache: true,
            ..Default::default()
        },
    )
    .unwrap();
    handshake.start().unwrap();
    assert!(matches!(
        handshake
            .receive(packets::Packet::NetworkSettings(Default::default()))
            .unwrap(),
        HandshakeEvent::Compression(_)
    ));
    handshake
        .login_offline(
            &OfflineIdentity {
                display_name: "Fixture",
                identity: "",
                xuid: "",
                playfab_id: "",
                playfab_title_id: "",
            },
            &RawValue::from_string("{}".into()).unwrap(),
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();
    let HandshakeEvent::Packs {
        cache_status,
        mut negotiation,
    } = handshake
        .receive(packets::Packet::ResourcePacksInfo(Default::default()))
        .unwrap()
    else {
        panic!("the offer must transfer its actual pack owner");
    };
    assert!(cache_status.unwrap().is_cache_supported);
    negotiation.start().unwrap();

    let early = [
        packets::Packet::SetTime(packets::SetTime {
            time: wire::ZigZag32(1),
        }),
        packets::Packet::PlayStatus(packets::PlayStatus {
            status: PlayStatusType::Playerspawn,
        }),
        packets::Packet::SetTime(packets::SetTime {
            time: wire::ZigZag32(2),
        }),
    ];
    let mut deferred = Vec::new();
    for packet in early.clone() {
        let PackEvent::Unhandled(packet) = negotiation.receive(packet).unwrap() else {
            panic!("startup input is not a pack transition");
        };
        let HandshakeEvent::Unhandled(packet) = handshake
            .receive(*packet)
            .expect("a successful early spawn indication must remain caller-owned")
        else {
            panic!("the handshake must return startup input unchanged");
        };
        deferred.push(*packet);
    }
    assert_eq!(deferred, early);

    let PackEvent::Unhandled(success) = negotiation
        .receive(packets::Packet::PlayStatus(packets::PlayStatus {
            status: PlayStatusType::Loginsuccess,
        }))
        .unwrap()
    else {
        panic!("late LoginSuccess remains handshake-owned");
    };
    assert!(matches!(
        handshake.receive(*success).unwrap(),
        HandshakeEvent::Send(sent) if sent.is_empty()
    ));
    assert!(matches!(
        negotiation
            .receive(packets::Packet::ResourcePackStack(Default::default()))
            .unwrap(),
        PackEvent::Finished { .. }
    ));

    let mut spawn = SpawnNegotiation::new(packets::RequestChunkRadius {
        chunk_radius: wire::ZigZag32(12),
        max_chunk_radius: wire::U8(16),
    })
    .unwrap();
    let mut play = Vec::new();
    for packet in deferred {
        let update = spawn.receive(packet).unwrap();
        assert!(update.ready.is_none());
        assert!(update.startup.is_none());
        assert!(update.request_radius.is_none());
        play.extend(update.deferred.map(|packet| *packet));
    }
    assert_eq!(play, [early[0].clone(), early[2].clone()]);
    assert!(spawn.finish_loading().is_err());
    let update = spawn
        .receive(packets::Packet::StartGame(Box::new(packets::StartGame {
            runtime_id: ActorRuntimeID(42),
            ..Default::default()
        })))
        .unwrap();
    assert_eq!(update.request_radius.unwrap().chunk_radius.0, 12);
    assert!(update.ready.is_none());
    let update = spawn
        .receive(packets::Packet::ItemRegistry(Default::default()))
        .unwrap();
    assert_eq!(update.startup.unwrap().start_game.runtime_id.0, 42);
    assert!(update.ready.is_none());
    let radius = packets::Packet::ChunkRadiusUpdated(packets::ChunkRadiusUpdated {
        chunk_radius: wire::ZigZag32(8),
    });
    let update = spawn.receive(radius.clone()).unwrap();
    assert_eq!(*update.deferred.unwrap(), radius);
    assert_eq!(
        update.ready.unwrap(),
        SpawnReady {
            runtime_id: 42,
            terrain_received: false,
        }
    );
    assert_eq!(spawn.finish_loading().unwrap().player_id.0, 42);
    assert!(spawn.finish_loading().is_err());
}
