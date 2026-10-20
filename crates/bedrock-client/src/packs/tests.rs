use super::transfer::Download;
use super::*;
use bedrock_protocol::{
    types::{PackInfoData, PackInstanceId},
    wire,
};
use bytes::Bytes;
use sha2::{Digest, Sha256};

mod optionality;

/// Exercises the generated server wire contract before retaining its original metadata.
fn server_wire(packet: packets::Packet) -> packets::Packet {
    let mut encoded = Vec::new();
    packet
        .encode_frame(wire::Peer::Server, 0, 0, &mut encoded)
        .unwrap();
    let mut frames = wire::Frames::new(encoded.into(), 1);
    let frame = frames.next().unwrap().unwrap();
    assert!(frames.next().is_none());
    let packets::Decoded::Known(decoded) =
        packets::Packet::decode_frame(&frame, wire::Peer::Server, &wire::Limits::default())
            .unwrap()
    else {
        panic!("metadata fixture remains a known generated server packet");
    };
    decoded
}

#[test]
fn completed_pack_metadata_keeps_actual_headers_order_and_data_only_when_requested() {
    for retain in [false, true] {
        let original = packets::ResourcePacksInfo {
            resource_pack_required: true,
            has_addon_packs: true,
            has_scripts: true,
            force_disable_vibrant_visuals: true,
            world_template_id_and_version: bedrock_protocol::types::PackIdVersion {
                pack_uuid: uuid::Uuid::from_u128(99),
                ..Default::default()
            },
            resource_packs: (1..=3)
                .map(|id| {
                    let mut pack = offer(uuid::Uuid::from_u128(id), 32);
                    pack.content_key = format!("original-key-{id}").into();
                    pack.subpack_name = "offered-subpack".into();
                    pack.cdn_url = "https://example.invalid/original-pack".into();
                    pack
                })
                .collect(),
        };
        let packets::Packet::ResourcePacksInfo(offer) = server_wire(original.clone().into()) else {
            panic!("original generated offer changed its role");
        };
        let offer = if retain {
            PackOffer::new_with_metadata(offer, PackTransferLimits::default())
        } else {
            PackOffer::new(offer, PackTransferLimits::default())
        }
        .unwrap();
        let (mut transfer, _) = offer.start().unwrap();
        let mut expected_data = Vec::new();
        for id in 1..=3 {
            let id = uuid::Uuid::from_u128(id);
            let bytes = fixture_bytes(id);
            let info = packets::ResourcePackDataInfo {
                resource_name: format!("{id}_1.0.0").into(),
                chunk_size: wire::U32LE(32),
                number_of_chunks: wire::U32LE(1),
                file_size: wire::U64LE(bytes.len() as u64),
                file_hash: Bytes::copy_from_slice(&Sha256::digest(&bytes)),
                is_premium_pack: id.as_u128() == 2,
                pack_type: wire::U8(6),
            };
            expected_data.push(info.clone());
            let PackEvent::Send(requests) = transfer.receive(server_wire(info.into())).unwrap()
            else {
                panic!("actual pack data did not request its original chunk");
            };
            assert_eq!(requests.len(), 1);
            let packets::Packet::ResourcePackChunkRequest(request) = &requests[0] else {
                panic!("actual data request changed its role");
            };
            assert_eq!(request.chunk.0, 0);
            assert!(matches!(
                transfer.receive(server_wire(
                    packets::ResourcePackChunkData {
                        resource_name: request.resource_name.clone(),
                        chunk_id: wire::U32LE(0),
                        byte_offset: wire::U64LE(0),
                        chunk_data: Bytes::from(bytes),
                    }
                    .into()
                )),
                Ok(PackEvent::Send(_))
            ));
        }
        let stack = packets::ResourcePackStack {
            texture_pack_required: true,
            texture_pack_list: [2, 1]
                .map(|id| PackInstanceId {
                    pack_id: uuid::Uuid::from_u128(id).to_string().into(),
                    version: "1.0.0".into(),
                    sub_pack_name: format!("selected-{id}").into(),
                })
                .into(),
            base_game_version: "original-selected-version".into(),
            include_editor_packs: true,
            experiments: bedrock_protocol::types::Experiments {
                toggles: vec![bedrock_protocol::types::ExperimentToggle {
                    name: "original-experiment".into(),
                    enabled: true,
                }],
                experiments_ever_toggled: true,
            },
        };
        let PackEvent::Finished(complete) =
            transfer.receive(server_wire(stack.clone().into())).unwrap()
        else {
            panic!("real final stack did not complete acquisition");
        };
        let (_, handoff, metadata) = complete.into_parts_with_metadata();
        assert!(handoff.required());
        let archives = handoff.into_archives();
        assert_eq!(
            archives
                .iter()
                .map(|pack| pack.pack_id.as_u128())
                .collect::<Vec<_>>(),
            [2, 1]
        );
        assert_eq!(archives[0].archive, fixture_bytes(uuid::Uuid::from_u128(2)));
        assert_eq!(archives[0].content_key.expose(), b"original-key-2");
        if retain {
            let metadata = metadata.expect("explicit metadata retention was lost");
            let mut projected = original;
            projected.resource_packs.truncate(2);
            for pack in &mut projected.resource_packs {
                pack.pack_size = wire::U64LE(16);
            }
            assert_eq!(metadata.offer, projected);
            assert_eq!(metadata.stack, stack);
            assert_eq!(metadata.data.len(), 2);
            assert_eq!(metadata.data[0].as_ref(), Some(&expected_data[0]));
            assert_eq!(metadata.data[1].as_ref(), Some(&expected_data[1]));
        } else {
            assert!(
                metadata.is_none(),
                "default transfer retained relay metadata"
            );
        }
    }
}

#[test]
fn retained_preloaded_metadata_does_not_manufacture_data_information() {
    let id = uuid::Uuid::from_u128(1);
    let mut offer = PackOffer::new_with_metadata(
        packets::ResourcePacksInfo {
            resource_packs: vec![offer(id, 32)],
            ..Default::default()
        },
        PackTransferLimits::default(),
    )
    .unwrap();
    offer.supply_preloaded(id, fixture_bytes(id)).unwrap();
    let (mut transfer, _) = offer.start().unwrap();
    let PackEvent::Finished(complete) = transfer
        .receive(
            packets::ResourcePackStack {
                texture_pack_list: vec![PackInstanceId {
                    pack_id: id.to_string().into(),
                    version: "1.0.0".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .into(),
        )
        .unwrap()
    else {
        panic!("actual preloaded selection did not finish");
    };
    let (_, _, metadata) = complete.into_parts_with_metadata();
    let metadata = metadata.unwrap();
    assert_eq!(metadata.offer.resource_packs[0].pack_size.0, 16);
    assert!(matches!(metadata.data.as_slice(), [None]));
}

/// Advertises original fixture bytes without production server identities.
fn offer(id: uuid::Uuid, size: usize) -> PackInfoData {
    let mut offer = PackInfoData::default();
    offer.pack_id_version.pack_uuid = id;
    offer.pack_id_version.pack_version.version = "1.0.0".into();
    offer.pack_size = wire::U64LE(size as u64);
    offer
}

/// Supplies distinct synthetic source bytes; archive admission belongs to the caller.
fn fixture_bytes(id: uuid::Uuid) -> Vec<u8> {
    id.as_bytes().to_vec()
}

/// Uses the production default policy for the retained transfer regressions.
fn admit(offers: Vec<PackInfoData>) -> (Vec<Download>, transfer::Budget) {
    transfer::Budget::offers(offers, PackTransferLimits::default())
}

/// Creates the bounded private transfer behind the public negotiation owner.
fn download(offer: PackInfoData) -> Result<Download, PackError> {
    Download::new(offer, PackTransferLimits::default())
}

/// Applies the final server stack with the same limits used at admission.
fn finish(
    downloads: BTreeMap<uuid::Uuid, Download>,
    stack: packets::ResourcePackStack,
    required: bool,
) -> Result<ResourcePackHandoff, PackError> {
    transfer::finish(
        downloads,
        stack,
        required,
        PackTransferLimits::default(),
        None,
        &[],
    )
    .map(|(handoff, _)| handoff)
}

/// Borrows completed retained bytes; an excluded or pending fixture is a test failure.
fn completed_bytes(download: &Download) -> &[u8] {
    match &download.complete {
        Some(transfer::Completion::Archive(bytes)) => bytes,
        _ => panic!("expected a completed retained archive"),
    }
}

/// Wraps one requested fragment with its original index and resource name.
fn chunk(download: &Download, index: u32, bytes: &[u8]) -> packets::ResourcePackChunkData {
    packets::ResourcePackChunkData {
        resource_name: download.name.clone(),
        chunk_id: wire::U32LE(index),
        chunk_data: Bytes::copy_from_slice(bytes),
        ..Default::default()
    }
}

#[test]
fn chunk_window_accepts_reordering_without_serializing_the_tail_and_checks_hashes() {
    let bytes = vec![7; DEFAULT_REQUEST_WINDOW as usize + 5];
    let (mut downloads, mut budget) = admit(vec![offer(uuid::Uuid::from_u128(1), bytes.len())]);
    let mut download = downloads.remove(0);
    let info = packets::ResourcePackDataInfo {
        resource_name: download.name.clone(),
        chunk_size: wire::U32LE(1),
        number_of_chunks: wire::U32LE(0),
        file_size: wire::U64LE(bytes.len() as u64),
        file_hash: Bytes::copy_from_slice(&Sha256::digest(&bytes)),
        ..Default::default()
    };
    let requests = budget.begin(&mut download, info.clone()).unwrap();
    assert_eq!(requests.len(), DEFAULT_REQUEST_WINDOW as usize);
    let late = chunk(&download, DEFAULT_REQUEST_WINDOW, &[7]);
    assert!(download.chunk(late).is_err());
    let mut replenished = Vec::new();
    for index in (0..DEFAULT_REQUEST_WINDOW).rev() {
        let packet = chunk(&download, index, &[7]);
        replenished.extend(download.chunk(packet).unwrap());
    }
    assert_eq!(replenished.len(), 5);
    for index in DEFAULT_REQUEST_WINDOW..bytes.len() as u32 {
        let packet = chunk(&download, index, &[7]);
        download.chunk(packet).unwrap();
    }
    assert_eq!(completed_bytes(&download), &bytes);
    let (mut downloads, mut budget) = admit(vec![offer(uuid::Uuid::from_u128(1), bytes.len())]);
    let mut bad = downloads.remove(0);
    let mut info = info;
    info.chunk_size = wire::U32LE(bytes.len() as u32);
    info.file_hash = Bytes::from_static(&[0; 32]);
    budget.begin(&mut bad, info).unwrap();
    let packet = chunk(&bad, 0, &bytes);
    assert!(bad.chunk(packet).is_err());
}

#[test]
fn final_stack_selects_order_subpack_and_offer_key_without_applying_unselected_archives() {
    let mut downloads = BTreeMap::new();
    for id in 1..=3 {
        let id = uuid::Uuid::from_u128(id);
        let bytes = if id.as_u128() == 3 {
            vec![1, 2, 3]
        } else {
            fixture_bytes(id)
        };
        let mut offered = offer(id, bytes.len());
        offered.content_key = "synthetic-content-key".into();
        offered.subpack_name = "offer-subpack".into();
        let mut download = download(offered).unwrap();
        download.complete = Some(transfer::Completion::Archive(Arc::new(bytes)));
        downloads.insert(id, download);
    }
    let mut stack = packets::ResourcePackStack {
        texture_pack_list: [2, 1]
            .into_iter()
            .map(|id| PackInstanceId {
                pack_id: uuid::Uuid::from_u128(id).to_string().into(),
                version: "1.0.0".into(),
                sub_pack_name: "stack-subpack".into(),
            })
            .collect(),
        ..Default::default()
    };
    stack.texture_pack_list.insert(
        0,
        PackInstanceId {
            pack_id: uuid::Uuid::from_u128(2).to_string().into(),
            version: "9.9.9".into(),
            ..Default::default()
        },
    );
    let handoff = finish(downloads, stack, false).unwrap();
    assert!(!handoff.required());
    let archives = handoff.into_archives();
    assert_eq!(
        archives
            .iter()
            .map(|archive| archive.pack_id.as_u128())
            .collect::<Vec<_>>(),
        [2, 1]
    );
    assert_eq!(archives[0].sub_pack_name, "stack-subpack");
    assert_eq!(archives[0].content_key.expose(), b"synthetic-content-key");
    let missing = PackInstanceId {
        pack_id: uuid::Uuid::from_u128(99).to_string().into(),
        version: "1.0.0".into(),
        ..Default::default()
    };
    let stack = packets::ResourcePackStack {
        texture_pack_list: vec![missing.clone()],
        ..Default::default()
    };
    assert!(
        finish(BTreeMap::new(), stack.clone(), false)
            .unwrap()
            .is_empty()
    );
    for selected in [
        vec![PackInstanceId {
            pack_id: "invalid-uuid".into(),
            ..missing.clone()
        }],
        vec![missing],
        vec![PackInstanceId {
            pack_id: uuid::Uuid::from_u128(1).to_string().into(),
            version: "9.9.9".into(),
            ..Default::default()
        }],
        vec![
            PackInstanceId {
                pack_id: uuid::Uuid::from_u128(1).to_string().into(),
                version: "1.0.0".into(),
                ..Default::default()
            };
            2
        ],
    ] {
        for (offer_required, stack_required) in [(true, false), (false, true), (true, true)] {
            let id = uuid::Uuid::from_u128(1);
            let bytes = fixture_bytes(id);
            let mut download = download(offer(id, bytes.len())).unwrap();
            download.complete = Some(transfer::Completion::Archive(Arc::new(bytes)));
            let stack = packets::ResourcePackStack {
                texture_pack_required: stack_required,
                texture_pack_list: selected.clone(),
                ..Default::default()
            };
            let result = finish([(id, download)].into(), stack, offer_required);
            if stack_required {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().required());
            }
        }
    }
}

#[test]
fn optional_content_admission_and_transfer_budget_are_separate() {
    let limits = PackTransferLimits {
        max_packs: Some(3),
        max_archive_bytes: Some(4),
        max_stack_bytes: Some(6),
        max_transfer_bytes: Some(12),
        ..Default::default()
    };
    let admit_bounded = |offers| transfer::Budget::offers(offers, limits);
    let id = uuid::Uuid::from_u128(1);
    let bytes = b"unsupported archive bytes";
    let mut oversized = offer(uuid::Uuid::from_u128(99), 0);
    oversized.pack_size = wire::U64LE(u64::MAX);
    let mut unusable = offer(uuid::Uuid::from_u128(98), 1);
    unusable.pack_id_version.pack_version.version = "".into();
    let (mut downloads, mut budget) = admit(vec![oversized, unusable, offer(id, bytes.len())]);
    assert_eq!(downloads.len(), 1);
    let mut download = downloads.remove(0);
    let info = packets::ResourcePackDataInfo {
        resource_name: download.name.clone(),
        chunk_size: wire::U32LE(bytes.len() as u32),
        file_size: wire::U64LE(bytes.len() as u64),
        file_hash: Bytes::copy_from_slice(&Sha256::digest(bytes)),
        ..Default::default()
    };
    budget.begin(&mut download, info).unwrap();
    let packet = chunk(&download, 0, bytes);
    download.chunk(packet).unwrap();
    let stack = packets::ResourcePackStack {
        texture_pack_list: vec![PackInstanceId {
            pack_id: id.to_string().into(),
            version: "1.0.0".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let handoff = finish([(id, download)].into(), stack.clone(), false).unwrap();
    assert!(!handoff.required());
    assert_eq!(handoff.into_archives()[0].archive, bytes);

    let (bounded, _) = admit_bounded(
        (1..=limits.max_packs.unwrap() + 1)
            .map(|index| offer(uuid::Uuid::from_u128(index as u128), 1))
            .collect(),
    );
    assert_eq!(bounded.len(), limits.max_packs.unwrap());

    for (offer_required, stack_required) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let (mut downloads, mut budget) = admit_bounded(vec![
            offer(id, 1),
            offer(
                uuid::Uuid::from_u128(2),
                limits.max_archive_bytes.unwrap() as usize,
            ),
            offer(
                uuid::Uuid::from_u128(3),
                limits.max_stack_bytes.unwrap() as usize
                    - limits.max_archive_bytes.unwrap() as usize
                    - 1,
            ),
            offer(uuid::Uuid::from_u128(4), 1),
        ]);
        assert_eq!(downloads.len(), 3);
        let mut download = downloads.remove(0);
        let bytes = b"12";
        let info = packets::ResourcePackDataInfo {
            resource_name: download.name.clone(),
            chunk_size: wire::U32LE(2),
            file_size: wire::U64LE(2),
            file_hash: Bytes::copy_from_slice(&Sha256::digest(bytes)),
            ..Default::default()
        };
        budget.begin(&mut download, info).unwrap();
        let packet = chunk(&download, 0, bytes);
        download.chunk(packet).unwrap();
        assert!(matches!(
            &download.complete,
            Some(transfer::Completion::Excluded)
        ));
        let stack = packets::ResourcePackStack {
            texture_pack_required: stack_required,
            ..stack.clone()
        };
        let result = finish([(id, download)].into(), stack, offer_required);
        if stack_required {
            assert!(result.is_err());
        } else {
            let handoff = result.unwrap();
            assert!(handoff.is_empty());
            assert_eq!(handoff.required(), offer_required);
        }
    }

    let (mut downloads, mut budget) = admit_bounded(vec![offer(id, 1)]);
    let mut download = downloads.remove(0);
    let info = packets::ResourcePackDataInfo {
        resource_name: download.name.clone(),
        chunk_size: wire::U32LE(1),
        file_size: wire::U64LE(limits.max_transfer_bytes.unwrap() + 1),
        file_hash: Bytes::from_static(&[0; 32]),
        ..Default::default()
    };
    assert!(budget.begin(&mut download, info).is_err());
}

/// Rejected metadata cannot reserve a UUID ahead of its first usable acquisition source.
#[test]
fn rejected_offer_does_not_poison_a_later_usable_uuid() {
    let id = uuid::Uuid::from_u128(1);
    let other = uuid::Uuid::from_u128(2);
    let bytes = fixture_bytes(id);
    let other_bytes = fixture_bytes(other);
    let mut rejected = offer(id, bytes.len() + 1);
    rejected.pack_id_version.pack_version.version = "2.0.0".into();
    let accepted = offer(id, bytes.len());
    let mut duplicate = accepted.clone();
    duplicate.pack_id_version.pack_version.version = "9.0.0".into();
    duplicate.cdn_url = "https://not-admitted.invalid/duplicate".into();
    let mut preloading = PackOffer::new(
        packets::ResourcePacksInfo {
            resource_pack_required: true,
            resource_packs: vec![
                rejected,
                accepted,
                duplicate,
                offer(other, other_bytes.len()),
            ],
            ..Default::default()
        },
        PackTransferLimits {
            max_archive_bytes: Some(bytes.len() as u64),
            ..Default::default()
        },
    )
    .unwrap();
    let admitted = preloading
        .offers()
        .map(|entry| {
            (
                entry.pack_id_version.pack_uuid,
                entry
                    .pack_id_version
                    .pack_version
                    .version
                    .to_string_lossy()
                    .into_owned(),
                entry.cdn_url.to_string_lossy().into_owned(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        admitted,
        vec![
            (id, "1.0.0".into(), String::new()),
            (other, "1.0.0".into(), String::new())
        ]
    );
    preloading.supply_preloaded(id, bytes.clone()).unwrap();
    preloading
        .supply_preloaded(other, other_bytes.clone())
        .unwrap();
    let (mut transfer, response) = preloading.start().unwrap();
    assert!(matches!(
        response.response,
        ResourcePackClientResponseData::DownloadingFinished { .. }
    ));
    let PackEvent::Finished(complete) = transfer
        .receive(
            packets::ResourcePackStack {
                texture_pack_list: [id, other]
                    .into_iter()
                    .map(|id| PackInstanceId {
                        pack_id: id.to_string().into(),
                        version: "1.0.0".into(),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            }
            .into(),
        )
        .unwrap()
    else {
        panic!("the first admitted source must satisfy its required stack once");
    };
    let (_, handoff) = complete.into_parts();
    let archives = handoff.into_archives();
    assert_eq!(archives.len(), 2);
    assert_eq!(archives[0].archive, bytes);
    assert_eq!(archives[1].archive, other_bytes);
}

#[test]
fn retained_metadata_and_out_of_order_fragment_release_the_shared_decoded_batches() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct BatchOwner {
        bytes: Vec<u8>,
        dropped: Arc<AtomicBool>,
    }
    impl AsRef<[u8]> for BatchOwner {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }
    impl Drop for BatchOwner {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Relaxed);
        }
    }
    let bytes = [7, 7];
    let (mut downloads, mut budget) = admit(vec![offer(uuid::Uuid::from_u128(1), bytes.len())]);
    let mut download = downloads.remove(0);
    let dropped_name = Arc::new(AtomicBool::new(false));
    let mut metadata = vec![0; 64 * 1024];
    let name_length = download.name.len();
    metadata[..name_length].copy_from_slice(download.name.as_bytes());
    let batch = Bytes::from_owner(BatchOwner {
        bytes: metadata,
        dropped: Arc::clone(&dropped_name),
    });
    let name = batch.slice(..name_length).into();
    drop(batch);
    budget
        .begin(
            &mut download,
            packets::ResourcePackDataInfo {
                resource_name: name,
                chunk_size: wire::U32LE(1),
                file_size: wire::U64LE(bytes.len() as u64),
                file_hash: Bytes::copy_from_slice(&Sha256::digest(bytes)),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(dropped_name.load(Ordering::Relaxed));
    let dropped = Arc::new(AtomicBool::new(false));
    let batch = Bytes::from_owner(BatchOwner {
        bytes: vec![7; 64 * 1024],
        dropped: Arc::clone(&dropped),
    });
    let packet = packets::ResourcePackChunkData {
        resource_name: download.name.clone(),
        chunk_id: wire::U32LE(1),
        chunk_data: batch.slice(123..124),
        ..Default::default()
    };
    drop(batch);
    download.chunk(packet).unwrap();
    assert!(dropped.load(Ordering::Relaxed));
    let packet = chunk(&download, 0, &bytes[..1]);
    download.chunk(packet).unwrap();
    assert_eq!(completed_bytes(&download), bytes);
}

#[test]
fn public_negotiation_preserves_preloads_request_order_and_final_stack_ownership() {
    let cached = uuid::Uuid::from_u128(2);
    let streamed = uuid::Uuid::from_u128(1);
    let data = b"abc";
    let mut offered = offer(streamed, data.len());
    offered.content_key = "synthetic-key".into();
    let mut negotiation = PackOffer::new(
        packets::ResourcePacksInfo {
            resource_pack_required: true,
            resource_packs: vec![offer(cached, 2), offered],
            ..Default::default()
        },
        PackTransferLimits {
            request_window: 2,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        negotiation
            .offers()
            .map(|offer| offer.pack_id_version.pack_uuid)
            .collect::<Vec<_>>(),
        [cached, streamed]
    );
    negotiation.supply_preloaded(cached, vec![9, 8]).unwrap();
    let name = format!("{streamed}_1.0.0");
    let (mut negotiation, response) = negotiation.start().unwrap();
    let ResourcePackClientResponseData::Downloading {
        downloading_packs, ..
    } = response.response
    else {
        panic!("the uncached archive needs an in-band request");
    };
    let expected_name: wire::Str = name.clone().into();
    assert_eq!(downloading_packs, [expected_name]);

    let unrelated = packets::Packet::from(packets::ClientCacheStatus {
        is_cache_supported: true,
    });
    let PackEvent::Unhandled(returned) = negotiation.receive(unrelated.clone()).unwrap() else {
        panic!("another client phase must retain its own packet");
    };
    assert_eq!(*returned, unrelated);

    let requests = sends(
        negotiation
            .receive(
                packets::ResourcePackDataInfo {
                    resource_name: name.clone().into(),
                    chunk_size: wire::U32LE(1),
                    number_of_chunks: wire::U32LE(999),
                    file_size: wire::U64LE(data.len() as u64),
                    file_hash: Bytes::copy_from_slice(&Sha256::digest(data)),
                    ..Default::default()
                }
                .into(),
            )
            .unwrap(),
    );
    assert_eq!(request_indices(requests), [0, 1]);
    for (index, expected) in [(1, vec![]), (1, vec![]), (0, vec![2])] {
        let replies = sends(
            negotiation
                .receive(
                    packets::ResourcePackChunkData {
                        resource_name: name.clone().into(),
                        chunk_id: wire::U32LE(index),
                        chunk_data: Bytes::copy_from_slice(&data[index as usize..=index as usize]),
                        ..Default::default()
                    }
                    .into(),
                )
                .unwrap(),
        );
        assert_eq!(request_indices(replies), expected);
    }
    let replies = sends(
        negotiation
            .receive(
                packets::ResourcePackChunkData {
                    resource_name: name.into(),
                    chunk_id: wire::U32LE(2),
                    chunk_data: Bytes::from_static(b"c"),
                    ..Default::default()
                }
                .into(),
            )
            .unwrap(),
    );
    assert!(matches!(
        replies.as_slice(),
        [packets::Packet::ResourcePackClientResponse(
            packets::ResourcePackClientResponse {
                response: ResourcePackClientResponseData::DownloadingFinished { .. },
            }
        )]
    ));
    let shared = negotiation.completed_archive(streamed).unwrap();
    assert_eq!(shared.as_slice(), data);
    drop(shared);
    let stack = packets::ResourcePackStack {
        texture_pack_list: [streamed, cached]
            .into_iter()
            .map(|id| PackInstanceId {
                pack_id: id.to_string().into(),
                version: "1.0.0".into(),
                sub_pack_name: "selected".into(),
            })
            .collect(),
        ..Default::default()
    };
    let PackEvent::Finished(complete) = negotiation.receive(stack.clone().into()).unwrap() else {
        panic!("the completed stack must transfer archive ownership");
    };
    let (response, handoff) = complete.into_parts();
    assert!(matches!(
        response.response,
        ResourcePackClientResponseData::ResourcePackStackFinished { .. }
    ));
    assert!(handoff.required());
    let archives = handoff.into_archives();
    assert_eq!(archives[0].pack_id, streamed);
    assert_eq!(archives[0].archive, data);
    assert_eq!(archives[0].sub_pack_name, "selected");
    assert_eq!(archives[0].content_key.expose(), b"synthetic-key");
    assert_eq!(archives[1].pack_id, cached);
    assert_eq!(archives[1].archive, [9, 8]);
    assert!(negotiation.receive(stack.into()).is_err());
}

/// Extracts generated responses from one successful transfer transition.
fn sends(event: PackEvent) -> Vec<packets::Packet> {
    match event {
        PackEvent::Send(packets) => packets,
        _ => panic!("expected in-band transfer responses"),
    }
}

#[test]
fn smaller_preloads_release_memory_and_in_band_transfer_reservations() {
    let cached = uuid::Uuid::from_u128(1);
    let streamed = uuid::Uuid::from_u128(2);
    let data = b"ab";
    // Exercise both retention and transfer admission with the same three-byte stack.
    for transfer_limit in [10, 20] {
        let mut negotiation = PackOffer::new(
            packets::ResourcePacksInfo {
                resource_pack_required: true,
                resource_packs: vec![offer(cached, 9), offer(streamed, 1)],
                ..Default::default()
            },
            PackTransferLimits {
                max_archive_bytes: Some(9),
                max_stack_bytes: Some(10),
                max_transfer_bytes: Some(transfer_limit),
                ..Default::default()
            },
        )
        .unwrap();
        negotiation.supply_preloaded(cached, vec![7]).unwrap();
        let (mut negotiation, _) = negotiation.start().unwrap();
        let name: wire::Str = format!("{streamed}_1.0.0").into();
        let requests = sends(
            negotiation
                .receive(
                    packets::ResourcePackDataInfo {
                        resource_name: name.clone(),
                        chunk_size: wire::U32LE(data.len() as u32),
                        file_size: wire::U64LE(data.len() as u64),
                        file_hash: Bytes::copy_from_slice(&Sha256::digest(data)),
                        ..Default::default()
                    }
                    .into(),
                )
                .expect("only the missing archive consumes the transfer budget"),
        );
        assert_eq!(request_indices(requests), [0]);
        negotiation
            .receive(
                packets::ResourcePackChunkData {
                    resource_name: name,
                    chunk_id: wire::U32LE(0),
                    chunk_data: Bytes::from_static(data),
                    ..Default::default()
                }
                .into(),
            )
            .unwrap();
        let stack = packets::ResourcePackStack {
            texture_pack_list: [cached, streamed]
                .into_iter()
                .map(|id| PackInstanceId {
                    pack_id: id.to_string().into(),
                    version: "1.0.0".into(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        let PackEvent::Finished(complete) = negotiation
            .receive(stack.into())
            .expect("the required stack retains only three bytes")
        else {
            panic!("the completed required stack must be handed off");
        };
        let (_, handoff) = complete.into_parts();
        let archives = handoff.into_archives();
        assert_eq!(archives.len(), 2);
        assert_eq!(archives[0].archive, [7]);
        assert_eq!(archives[1].archive, data);
    }
}

/// An unrelated offered version cannot hide the exact built-in tuple selected by a required stack.
#[test]
fn required_builtin_selection_survives_a_downloaded_version_mismatch() {
    let catalog: serde_json::Value =
        serde_json::from_str(include_str!("../../data/builtin-packs.json")).unwrap();
    let builtin = &catalog["packs"][0];
    let id = uuid::Uuid::parse_str(builtin["id"].as_str().unwrap()).unwrap();
    let version = builtin["version"].as_str().unwrap();
    let downloaded_version = format!("{version}-different-offer");
    let make = |offered_version: &str, offer_required| {
        let mut offered = offer(id, 2);
        offered.pack_id_version.pack_version.version = offered_version.into();
        let mut client = PackOffer::new(
            packets::ResourcePacksInfo {
                resource_pack_required: offer_required,
                resource_packs: vec![offered],
                ..Default::default()
            },
            PackTransferLimits::default(),
        )
        .unwrap();
        client.supply_preloaded(id, vec![7, 8]).unwrap();
        client.start().unwrap().0
    };
    let stack = |selected_version: &str, required| packets::ResourcePackStack {
        texture_pack_required: required,
        texture_pack_list: vec![PackInstanceId {
            pack_id: id.to_string().into(),
            version: selected_version.into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    for (offer_required, stack_required) in [(true, false), (false, true), (true, true)] {
        let mut client = make(&downloaded_version, offer_required);
        let PackEvent::Finished(complete) = client.receive(stack(version, stack_required).into())
            .expect("a selected catalogued built-in remains available despite another downloaded version")
        else { panic!("required built-in stack did not finish"); };
        let (_, handoff) = complete.into_parts();
        assert!(handoff.required());
        assert!(
            handoff.is_empty(),
            "an unselected version must not be applied as the built-in"
        );
    }
    let mut override_client = make(version, true);
    let PackEvent::Finished(complete) = override_client
        .receive(stack(version, false).into())
        .unwrap()
    else {
        panic!("matching downloaded override did not finish");
    };
    let (_, handoff) = complete.into_parts();
    assert_eq!(handoff.into_archives()[0].archive, [7, 8]);
    let mut unavailable = make(&downloaded_version, true);
    assert!(
        unavailable
            .receive(stack(&format!("{version}-not-catalogued"), false).into())
            .is_err()
    );
}

/// Asserts that every response in a request window is an actual generated chunk request.
fn request_indices(packets: Vec<packets::Packet>) -> Vec<i32> {
    packets
        .into_iter()
        .map(|packet| match packet {
            packets::Packet::ResourcePackChunkRequest(request) => request.chunk.0,
            _ => panic!("expected a generated chunk request"),
        })
        .collect()
}

mod compatible_limits;
