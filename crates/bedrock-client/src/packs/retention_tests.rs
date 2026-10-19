use super::*;
use bedrock_protocol::{types, wire};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::sync::Weak;

/// Keeps a real generated batch observable without changing the packet decoder.
struct BatchOwner(Arc<Vec<u8>>);

impl AsRef<[u8]> for BatchOwner {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Decodes both actual siblings and returns only the metadata packet's shared slices.
fn coalesced(packet: packets::Packet) -> (packets::Packet, Weak<Vec<u8>>) {
    let mut encoded = Vec::new();
    packet
        .encode_frame(wire::Peer::Server, 0, 0, &mut encoded)
        .unwrap();
    packets::Packet::from(packets::Text {
        body: types::TextData::MessageOnly {
            message_type: Default::default(),
            message: "x".repeat(16 * 1024).into(),
        },
        ..Default::default()
    })
    .encode_frame(wire::Peer::Server, 0, 0, &mut encoded)
    .unwrap();
    let owner = Arc::new(encoded);
    let backing = Arc::downgrade(&owner);
    let mut frames = wire::Frames::new(Bytes::from_owner(BatchOwner(owner)), 2);
    let frame = frames.next().unwrap().unwrap();
    let packets::Decoded::Known(packet) =
        packets::Packet::decode_frame(&frame, wire::Peer::Server, &wire::Limits::default())
            .unwrap()
    else {
        panic!("the metadata packet must pass the actual generated decoder");
    };
    let sibling = frames.next().unwrap().unwrap();
    assert!(matches!(
        packets::Packet::decode_frame(&sibling, wire::Peer::Server, &wire::Limits::default())
            .unwrap(),
        packets::Decoded::Known(packets::Packet::Text(_))
    ));
    assert!(frames.next().is_none());
    assert!(backing.upgrade().is_some());
    (packet, backing)
}

#[test]
fn retained_pack_metadata_releases_unrelated_decoded_batch_siblings() {
    let id = uuid::Uuid::from_u128(1);
    let archive = b"synthetic acquired archive";
    let original_offer = packets::ResourcePacksInfo {
        resource_pack_required: true,
        world_template_id_and_version: types::PackIdVersion {
            pack_version: types::SemVersion {
                version: "template-version".into(),
            },
            ..Default::default()
        },
        resource_packs: vec![types::PackInfoData {
            pack_id_version: types::PackIDVersionData {
                pack_uuid: id,
                pack_version: types::SemVersionData {
                    version: "1.0.0".into(),
                },
            },
            pack_size: wire::U64LE(archive.len() as u64),
            content_key: "original-key".into(),
            subpack_name: "offered-subpack".into(),
            content_identity: types::ContentIdentity {
                identity: "original-content-identity".into(),
            },
            cdn_url: "https://example.invalid/pack".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let (packets::Packet::ResourcePacksInfo(offer), offer_backing) =
        coalesced(original_offer.clone().into())
    else {
        panic!("the generated offer changed packet role");
    };
    let (mut transfer, _) = PackOffer::new_with_metadata(offer, PackTransferLimits::default())
        .unwrap()
        .start()
        .unwrap();
    let original_info = packets::ResourcePackDataInfo {
        resource_name: format!("{id}_1.0.0").into(),
        chunk_size: wire::U32LE(archive.len() as u32),
        number_of_chunks: wire::U32LE(1),
        file_size: wire::U64LE(archive.len() as u64),
        file_hash: Bytes::copy_from_slice(&Sha256::digest(archive)),
        is_premium_pack: true,
        pack_type: wire::U8(6),
    };
    let (info, info_backing) = coalesced(original_info.clone().into());
    assert!(matches!(transfer.receive(info), Ok(PackEvent::Send(_))));
    assert!(matches!(
        transfer.receive(
            packets::ResourcePackChunkData {
                resource_name: original_info.resource_name.clone(),
                chunk_data: Bytes::copy_from_slice(archive),
                ..Default::default()
            }
            .into()
        ),
        Ok(PackEvent::Send(_))
    ));
    let original_stack = packets::ResourcePackStack {
        texture_pack_required: true,
        texture_pack_list: vec![types::PackInstanceId {
            pack_id: id.to_string().into(),
            version: "1.0.0".into(),
            sub_pack_name: "selected-subpack".into(),
        }],
        base_game_version: "original-base-version".into(),
        experiments: types::Experiments {
            toggles: vec![types::ExperimentToggle {
                name: "original-experiment".into(),
                enabled: true,
            }],
            experiments_ever_toggled: true,
        },
        include_editor_packs: true,
    };
    let (stack, stack_backing) = coalesced(original_stack.clone().into());
    let PackEvent::Finished(complete) = transfer.receive(stack).unwrap() else {
        panic!("the actual acquired stack must complete");
    };
    let (_, handoff, metadata) = complete.into_parts_with_metadata();
    let metadata = metadata.unwrap();
    assert_eq!(metadata.offer, original_offer);
    assert_eq!(metadata.stack, original_stack);
    assert_eq!(metadata.data, [Some(original_info)]);
    assert_eq!(handoff.into_archives()[0].archive, archive);
    drop(transfer);
    let backings = [offer_backing, info_backing, stack_backing];
    let released_while_metadata_retained =
        backings.each_ref().map(|owner| owner.upgrade().is_none());
    drop(metadata);
    assert!(backings.iter().all(|owner| owner.upgrade().is_none()));
    assert_eq!(
        released_while_metadata_retained, [true; 3],
        "retained offer, data info or stack pinned an unrelated decoded sibling"
    );
}
