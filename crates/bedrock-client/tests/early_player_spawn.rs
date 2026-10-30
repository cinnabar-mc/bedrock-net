//! Retains early startup input through the public handshake, pack and spawn owners.

use bedrock_client::handshake::{
    ClientHandshake, HandshakeOptions, LoginEvent, PacksEvent, SettingsEvent,
};
use bedrock_net::login::OfflineIdentity;
use bedrock_protocol::{enums::PlayStatusType, packets, types::ActorRuntimeID, wire};
use p384::ecdsa::SigningKey;
use serde_json::value::RawValue;
use std::time::SystemTime;

#[test]
fn early_player_spawn_survives_pack_and_handshake_owners_until_startup() {
    let configured = ClientHandshake::new(
        SigningKey::from_slice(&[1; 48]).unwrap(),
        HandshakeOptions {
            blob_cache: true,
            ..Default::default()
        },
    )
    .unwrap();
    let (settings, _) = configured.start().unwrap();
    let SettingsEvent::Ready { login, .. } = settings
        .receive(packets::Packet::NetworkSettings(Default::default()))
        .unwrap()
    else {
        panic!("the parsed settings must transfer actual Login readiness");
    };
    let (handshake, _) = login
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
    let LoginEvent::Packs {
        cache_status,
        packs,
    } = handshake
        .receive(packets::Packet::ResourcePacksInfo(Default::default()))
        .unwrap()
    else {
        panic!("the offer must transfer its actual pack and late control owners");
    };
    assert!(cache_status.unwrap().is_cache_supported);
    let (mut negotiation, _) = packs.start().unwrap();

    let early = [
        packets::Packet::SetTime(packets::SetTime {
            time: wire::ZigZag32(1),
        }),
        packets::Packet::PlayStatus(packets::PlayStatus {
            status: PlayStatusType::PlayerSpawn,
        }),
        packets::Packet::SetTime(packets::SetTime {
            time: wire::ZigZag32(2),
        }),
    ];
    let mut deferred = Vec::new();
    for packet in early.clone() {
        let PacksEvent::Unhandled { packs, packet } = negotiation
            .receive(packet)
            .expect("a successful early spawn indication must remain caller-owned")
        else {
            panic!("the pack/control owner must return startup input unchanged");
        };
        negotiation = packs;
        deferred.push(*packet);
    }
    assert_eq!(deferred, early);
    let PacksEvent::Send {
        packs,
        packets: sent,
    } = negotiation
        .receive(packets::Packet::PlayStatus(packets::PlayStatus {
            status: PlayStatusType::LoginSuccess,
        }))
        .unwrap()
    else {
        panic!("late LoginSuccess remains on the same pack/control owner");
    };
    assert!(sent.is_empty());
    let PacksEvent::Finished(complete) = packs
        .receive(packets::Packet::ResourcePackStack(Default::default()))
        .unwrap()
    else {
        panic!("the actual final stack must transfer completion");
    };
    let (mut spawn, _, handoff) = complete
        .start_spawn(packets::RequestChunkRadius {
            chunk_radius: wire::ZigZag32(12),
            max_chunk_radius: wire::U8(16),
        })
        .unwrap();
    assert!(handoff.is_empty());
    let mut play = Vec::new();
    for packet in deferred {
        let update = spawn.receive(packet).unwrap();
        assert!(update.ready.is_none());
        assert!(update.startup.is_none());
        assert!(update.request_radius.is_none());
        play.extend(update.deferred.map(|packet| *packet));
    }
    assert_eq!(play, [early[0].clone(), early[2].clone()]);
    let update = spawn
        .receive(packets::Packet::StartGame(Box::new(packets::StartGame {
            runtime_id: ActorRuntimeID(42),
            ..Default::default()
        })))
        .unwrap();
    assert_eq!(update.request_radius.unwrap().chunk_radius.0, 12);
    assert!(update.ready.is_none());
    let radius = packets::Packet::ChunkRadiusUpdated(packets::ChunkRadiusUpdated {
        chunk_radius: wire::ZigZag32(8),
    });
    let update = spawn.receive(radius.clone()).unwrap();
    assert_eq!(*update.deferred.unwrap(), radius);
    assert!(update.ready.is_none());
    let update = spawn
        .receive(packets::Packet::ItemRegistry(Default::default()))
        .unwrap();
    assert_eq!(update.startup.unwrap().start_game.runtime_id.0, 42);
    let ready = update.ready.unwrap();
    assert_eq!(ready.runtime_id(), 42);
    assert!(!ready.terrain_received());
    assert_eq!(ready.finish_loading().player_id.0, 42);
}
