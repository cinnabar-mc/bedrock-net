use super::*;

#[test]
fn chunk_transfer_ignores_hash_and_resource_version_suffixes() {
    for hash in [
        Bytes::new(),
        Bytes::from_static(b"short"),
        Bytes::from_static(&[0; 32]),
    ] {
        let id = uuid::Uuid::from_u128(1);
        let (mut downloads, mut budget) = admit(vec![offer(id, 3)]);
        let mut download = downloads.remove(0);
        let info = packets::ResourcePackDataInfo {
            resource_name: format!("{id}_different-version").into(),
            chunk_size: wire::U32LE(3),
            file_size: wire::U64LE(3),
            file_hash: hash,
            ..Default::default()
        };
        assert_eq!(budget.begin(&mut download, info).unwrap().len(), 1);
        let mut data = chunk(&download, 0, b"abc");
        data.resource_name = format!("{id}_another-version").into();
        download.chunk(data).unwrap();
        assert_eq!(completed_bytes(&download), b"abc");
    }
}

#[test]
fn default_offer_admission_keeps_empty_long_and_non_utf8_versions() {
    for version in [
        Bytes::new(),
        Bytes::from(vec![b'v'; 257]),
        Bytes::from_static(b"\xff"),
    ] {
        let id = uuid::Uuid::from_u128(1);
        let mut entry = offer(id, 3);
        entry.pack_id_version.pack_version.version = version.clone().into();
        let (mut downloads, mut budget) = admit(vec![entry]);
        assert_eq!(downloads.len(), 1);
        let mut download = downloads.remove(0);
        let info = packets::ResourcePackDataInfo {
            resource_name: download.name.clone(),
            chunk_size: wire::U32LE(3),
            file_size: wire::U64LE(3),
            ..Default::default()
        };
        budget.begin(&mut download, info).unwrap();
        let data = chunk(&download, 0, b"abc");
        download.chunk(data).unwrap();
        assert_eq!(completed_bytes(&download), b"abc");
    }
    let mut entry = offer(uuid::Uuid::from_u128(1), 3);
    entry.pack_id_version.pack_version.version = "long".into();
    let (downloads, _) = transfer::Budget::offers(
        vec![entry],
        PackTransferLimits {
            max_version_bytes: 3,
            ..Default::default()
        },
    );
    assert!(downloads.is_empty(), "explicit caller limits still apply");
}

#[test]
fn required_stack_accepts_repeated_downloaded_entries() {
    let id = uuid::Uuid::from_u128(1);
    let mut offer = PackOffer::new_with_metadata(
        packets::ResourcePacksInfo {
            resource_packs: vec![offer(id, 3)],
            ..Default::default()
        },
        PackTransferLimits::default(),
    )
    .unwrap();
    offer.supply_preloaded(id, b"abc".to_vec()).unwrap();
    let (mut transfer, _) = offer.start().unwrap();
    let entry = PackInstanceId {
        pack_id: id.to_string().into(),
        version: "1.0.0".into(),
        ..Default::default()
    };
    let PackEvent::Finished(complete) = transfer
        .receive(
            packets::ResourcePackStack {
                texture_pack_required: true,
                texture_pack_list: vec![entry.clone(), entry],
                ..Default::default()
            }
            .into(),
        )
        .unwrap()
    else {
        panic!("stack must complete");
    };
    let (_, handoff, metadata) = complete.into_parts_with_metadata();
    assert_eq!(handoff.len(), 1);
    assert_eq!(metadata.unwrap().stack.texture_pack_list.len(), 2);
}

#[test]
fn repeated_stack_rows_validate_each_version_in_either_order() {
    let id = uuid::Uuid::from_u128(1);
    for required in [false, true] {
        for versions in [["1.0.0", "9.9.9"], ["9.9.9", "1.0.0"]] {
            let mut offered = PackOffer::new_with_metadata(
                packets::ResourcePacksInfo {
                    resource_packs: vec![offer(id, 3)],
                    ..Default::default()
                },
                PackTransferLimits::default(),
            )
            .unwrap();
            offered.supply_preloaded(id, b"abc".to_vec()).unwrap();
            let (mut transfer, _) = offered.start().unwrap();
            let result = transfer.receive(
                packets::ResourcePackStack {
                    texture_pack_required: required,
                    texture_pack_list: versions
                        .map(|version| PackInstanceId {
                            pack_id: id.to_string().into(),
                            version: version.into(),
                            ..Default::default()
                        })
                        .into(),
                    ..Default::default()
                }
                .into(),
            );
            if required {
                assert!(result.is_err());
            } else {
                let PackEvent::Finished(complete) = result.unwrap() else {
                    panic!("optional stack completes");
                };
                let (_, handoff, metadata) = complete.into_parts_with_metadata();
                assert_eq!(handoff.len(), 1);
                let stack = metadata.unwrap().stack;
                assert_eq!(stack.texture_pack_list.len(), 1);
                assert_eq!(
                    stack.texture_pack_list[0].version.to_str().unwrap(),
                    "1.0.0"
                );
            }
        }
    }
}

#[test]
fn repeated_excluded_rows_cannot_restore_unavailable_relay_metadata() {
    let id = uuid::Uuid::from_u128(1);
    let (mut transfer, _) = PackOffer::new_with_metadata(
        packets::ResourcePacksInfo {
            resource_packs: vec![offer(id, 1)],
            ..Default::default()
        },
        PackTransferLimits {
            max_archive_bytes: Some(1),
            max_transfer_bytes: Some(2),
            ..Default::default()
        },
    )
    .unwrap()
    .start()
    .unwrap();
    transfer
        .receive(
            packets::ResourcePackDataInfo {
                resource_name: id.to_string().into(),
                chunk_size: wire::U32LE(2),
                file_size: wire::U64LE(2),
                ..Default::default()
            }
            .into(),
        )
        .unwrap();
    transfer
        .receive(
            packets::ResourcePackChunkData {
                resource_name: id.to_string().into(),
                chunk_data: Bytes::from_static(b"ab"),
                ..Default::default()
            }
            .into(),
        )
        .unwrap();
    let entry = PackInstanceId {
        pack_id: id.to_string().into(),
        version: "1.0.0".into(),
        ..Default::default()
    };
    let PackEvent::Finished(complete) = transfer
        .receive(
            packets::ResourcePackStack {
                texture_pack_list: vec![entry.clone(), entry],
                ..Default::default()
            }
            .into(),
        )
        .unwrap()
    else {
        panic!("optional excluded stack completes");
    };
    let (_, handoff, metadata) = complete.into_parts_with_metadata();
    let metadata = metadata.unwrap();
    assert!(handoff.is_empty());
    assert!(metadata.offer.resource_packs.is_empty());
    assert!(metadata.stack.texture_pack_list.is_empty());
    assert!(metadata.data.is_empty());
}

#[test]
fn client_chunk_count_includes_the_last_signed_request_index() {
    for (size, valid) in [(1_u64 << 31, true), ((1_u64 << 31) + 1, false)] {
        let id = uuid::Uuid::from_u128(1);
        let (mut transfer, _) = PackOffer::new(
            packets::ResourcePacksInfo {
                resource_packs: vec![offer(id, 1)],
                ..Default::default()
            },
            PackTransferLimits::default(),
        )
        .unwrap()
        .start()
        .unwrap();
        let result = transfer.receive(
            packets::ResourcePackDataInfo {
                resource_name: id.to_string().into(),
                chunk_size: wire::U32LE(1),
                file_size: wire::U64LE(size),
                ..Default::default()
            }
            .into(),
        );
        assert_eq!(result.is_ok(), valid);
        if let Ok(PackEvent::Send(requests)) = result {
            assert_eq!(requests.len(), DEFAULT_REQUEST_WINDOW as usize);
        }
    }
}
