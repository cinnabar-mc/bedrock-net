use super::transfer::Download;
use super::*;
use bedrock_protocol::{
    types::{PackInfoData, PackInstanceId},
    wire,
};
use bytes::Bytes;
use sha2::{Digest, Sha256};

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
    transfer::finish(downloads, stack, required, PackTransferLimits::default())
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
            assert!(finish([(id, download)].into(), stack, offer_required).is_err());
        }
    }
}

#[test]
fn optional_content_admission_and_transfer_budget_are_separate() {
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

    let (bounded, _) = admit(
        (1..=bedrock_packs::MAX_PACKS + 1)
            .map(|index| offer(uuid::Uuid::from_u128(index as u128), 1))
            .collect(),
    );
    assert_eq!(bounded.len(), bedrock_packs::MAX_PACKS);

    for (offer_required, stack_required) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let (mut downloads, mut budget) = admit(vec![
            offer(id, 1),
            offer(uuid::Uuid::from_u128(2), bedrock_packs::MAX_ARCHIVE_BYTES),
            offer(
                uuid::Uuid::from_u128(3),
                bedrock_packs::MAX_STACK_ARCHIVE_BYTES - bedrock_packs::MAX_ARCHIVE_BYTES - 1,
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
        if offer_required || stack_required {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_empty());
        }
    }

    let (mut downloads, mut budget) = admit(vec![offer(id, 1)]);
    let mut download = downloads.remove(0);
    let info = packets::ResourcePackDataInfo {
        resource_name: download.name.clone(),
        chunk_size: wire::U32LE(1),
        file_size: wire::U64LE(PackTransferLimits::default().max_transfer_bytes + 1),
        file_hash: Bytes::from_static(&[0; 32]),
        ..Default::default()
    };
    assert!(budget.begin(&mut download, info).is_err());
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
    let mut negotiation = PackNegotiation::new(
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
    let response = negotiation.start().unwrap();
    let ResourcePackClientResponseData::Downloading {
        downloading_packs, ..
    } = response.response
    else {
        panic!("the uncached archive needs an in-band request");
    };
    let expected_name: wire::Str = name.clone().into();
    assert_eq!(downloading_packs, [expected_name]);
    assert!(negotiation.start().is_err());
    assert!(
        negotiation
            .supply_preloaded(streamed, data.to_vec())
            .is_err()
    );

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
    let PackEvent::Finished { response, handoff } =
        negotiation.receive(stack.clone().into()).unwrap()
    else {
        panic!("the completed stack must transfer archive ownership");
    };
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
