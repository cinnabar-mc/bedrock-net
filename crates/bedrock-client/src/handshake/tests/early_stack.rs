use super::*;
use bedrock_protocol::types::{PackIDVersionData, PackInfoData, PackInstanceId, SemVersionData};
use bytes::Bytes;
use sha2::{Digest, Sha256};

/// The typed lifecycle preserves one owner across early-stack deferral, transfer effects and replay.
#[test]
fn typed_packs_replay_an_early_stack_after_the_original_download() {
    let (client, _) = ClientHandshake::new(
        SigningKey::from_slice(&[1; 48]).unwrap(),
        HandshakeOptions::default(),
    )
    .unwrap()
    .start()
    .unwrap();
    let SettingsEvent::Ready { login, .. } = client
        .receive(packets::NetworkSettings::default().into())
        .unwrap()
    else {
        panic!("settings")
    };
    let (client, _) = login
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
    let id = uuid::Uuid::from_u128(1);
    let LoginEvent::Packs { packs, .. } = client
        .receive(
            packets::ResourcePacksInfo {
                resource_packs: vec![PackInfoData {
                    pack_id_version: PackIDVersionData {
                        pack_uuid: id,
                        pack_version: SemVersionData {
                            version: "1.0.0".into(),
                        },
                    },
                    pack_size: wire::U64LE(3),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .into(),
        )
        .unwrap()
    else {
        panic!("offer")
    };
    let (packs, _) = packs.start().unwrap();
    assert!(!packs.ready_for_stack());
    let original = packets::ResourcePackStack {
        texture_pack_required: true,
        texture_pack_list: vec![PackInstanceId {
            pack_id: id.to_string().into(),
            version: "1.0.0".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let PacksEvent::DeferredStack { packs, stack } =
        packs.receive(original.clone().into()).unwrap()
    else {
        panic!("early stack")
    };
    assert_eq!(*stack, original);
    assert!(!packs.ready_for_stack());
    let name = format!("{id}_1.0.0");
    let PacksEvent::Send { packs, packets } = packs
        .receive(
            packets::ResourcePackDataInfo {
                resource_name: name.clone().into(),
                chunk_size: wire::U32LE(3),
                file_size: wire::U64LE(3),
                file_hash: Bytes::copy_from_slice(&Sha256::digest(b"abc")),
                ..Default::default()
            }
            .into(),
        )
        .unwrap()
    else {
        panic!("requests")
    };
    assert!(matches!(
        packets.as_slice(),
        [packets::Packet::ResourcePackChunkRequest(_)]
    ));
    let PacksEvent::Send { packs, packets } = packs
        .receive(
            packets::ResourcePackChunkData {
                resource_name: name.into(),
                chunk_data: Bytes::from_static(b"abc"),
                ..Default::default()
            }
            .into(),
        )
        .unwrap()
    else {
        panic!("download completion")
    };
    assert!(matches!(
        packets.as_slice(),
        [packets::Packet::ResourcePackClientResponse(_)]
    ));
    assert!(packs.ready_for_stack());
    let PacksEvent::Finished(complete) = packs.receive((*stack).into()).unwrap() else {
        panic!("replay completion")
    };
    let (_, handoff) = complete.into_parts();
    assert_eq!(handoff.into_archives()[0].archive, b"abc");
}
